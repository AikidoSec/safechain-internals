//go:build darwin

package certconfig

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

const javaTrustAlias = "aikido-safechain-proxy-ca"

var darwinJavaHomeRE = regexp.MustCompile(`(/.*(?:/Contents/Home|/Home))\s*$`)

type javaTrustTarget struct {
	javaHome    string
	keytoolPath string
	cacertsPath string
}

func installJavaTrust(ctx context.Context) error {
	jdkTargets := darwinJavaTrustTargets(ctx)
	if len(jdkTargets) == 0 {
		log.Printf("java: no JDKs found, skipping truststore configuration")
		return nil
	}

	caPath := proxy.GetCaCertPath()
	if _, err := os.Stat(caPath); err != nil {
		return fmt.Errorf("java: failed to stat downloaded proxy CA %s: %w", caPath, err)
	}

	var errs []error
	for _, target := range jdkTargets {
		if err := syncJavaTrustTarget(ctx, target, caPath); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("java: failed to sync truststore entries: %v", errs)
	}
	return nil
}

// javaNeedsRepair intentionally always returns false. Detecting a drifted Java
// truststore would require shelling out to keytool per JDK on every heartbeat
// and parsing its locale-dependent output. Since any other configurator's drift
// triggers a full certconfig.Install (which re-runs installJavaTrust), newly
// added JDKs are picked up reactively without this proactive check.
func javaNeedsRepair(_ context.Context) bool {
	return false
}

func uninstallJavaTrust(ctx context.Context) error {
	jdkTargets := darwinJavaTrustTargets(ctx)
	if len(jdkTargets) == 0 {
		log.Printf("java: no JDKs found, skipping truststore cleanup")
		return nil
	}
	for _, target := range jdkTargets {
		if javaTrustAliasExists(ctx, target) {
			deleteJavaTrustAlias(ctx, target)
		}
	}
	return nil
}

func syncJavaTrustTarget(ctx context.Context, target javaTrustTarget, caPath string) error {
	// keytool has no upsert. Probe first, then delete only if needed, then
	// import. Probing avoids the noisy "alias does not exist" error that
	// keytool emits on every fresh JDK during its first install.
	if javaTrustAliasExists(ctx, target) {
		deleteJavaTrustAlias(ctx, target)
	}

	output, err := runKeytoolForTarget(ctx, target,
		"-importcert",
		"-noprompt",
		"-trustcacerts",
		"-alias", javaTrustAlias,
		"-file", caPath,
		"-keystore", target.cacertsPath,
		"-storepass", "changeit",
	)
	if err != nil {
		return fmt.Errorf("java: keytool import failed for %s: %w (output: %s)", target.cacertsPath, err, strings.TrimSpace(output))
	}
	return nil
}

// javaTrustAliasExists checks whether our managed alias is already present in
// the target's cacerts.
func javaTrustAliasExists(ctx context.Context, target javaTrustTarget) bool {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	_, err := utils.RunCommand(quietCtx, target.keytoolPath,
		"-list",
		"-alias", javaTrustAlias,
		"-keystore", target.cacertsPath,
		"-storepass", "changeit",
	)
	return err == nil
}

// deleteJavaTrustAlias is best-effort: the import that follows is the ground
// truth. Callers should gate this on javaTrustAliasExists — keytool's
// stderr output for a missing alias is uninformative noise.
func deleteJavaTrustAlias(ctx context.Context, target javaTrustTarget) {
	output, err := runKeytoolForTarget(ctx, target,
		"-delete",
		"-alias", javaTrustAlias,
		"-keystore", target.cacertsPath,
		"-storepass", "changeit",
	)
	if err != nil {
		log.Printf("java: keytool delete for %s reported %v (output: %s); continuing", target.cacertsPath, err, strings.TrimSpace(output))
	}
}

// runKeytoolForTarget invokes keytool under the right identity for the target's
// cacerts ownership. System JDKs live under /Library and their cacerts are
// owned by root — those require the daemon's root privileges to write. JDKs
// managed by the user (e.g. JetBrains in ~/Library) have user-owned cacerts;
// dropping to that user preserves ownership and matches how the other
// user-scoped configurators operate.
func runKeytoolForTarget(ctx context.Context, target javaTrustTarget, args ...string) (string, error) {
	info, err := os.Stat(target.cacertsPath)
	if err != nil {
		return "", fmt.Errorf("stat cacerts %s: %w", target.cacertsPath, err)
	}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok && sys.Uid == 0 {
		return utils.RunCommand(ctx, target.keytoolPath, args...)
	}
	return platform.RunAsCurrentUserWithPathEnv(ctx, target.keytoolPath, args...)
}

func darwinJavaTrustTargets(ctx context.Context) []javaTrustTarget {
	seen := map[string]struct{}{}
	var homes []string

	for _, home := range javaHomesFromJavaHomeTool(ctx) {
		homes = appendIfMissingCanonicalHome(homes, seen, home)
	}
	for _, home := range javaHomesFromJetBrains(platform.GetConfig().HomeDir) {
		homes = appendIfMissingCanonicalHome(homes, seen, home)
	}
	for _, home := range javaHomesFromJetBrainsRuntime() {
		homes = appendIfMissingCanonicalHome(homes, seen, home)
	}
	for _, home := range javaHomesFromHomebrew() {
		homes = appendIfMissingCanonicalHome(homes, seen, home)
	}
	for _, home := range javaHomesFromVersionManagers(platform.GetConfig().HomeDir) {
		homes = appendIfMissingCanonicalHome(homes, seen, home)
	}

	jdkTargets := make([]javaTrustTarget, 0, len(homes))
	for _, home := range homes {
		target, ok := javaTrustTargetFromHome(home)
		if ok {
			jdkTargets = append(jdkTargets, target)
		}
	}
	return jdkTargets
}

func javaHomesFromJavaHomeTool(ctx context.Context) []string {
	output, err := platform.RunAsCurrentUserWithPathEnv(ctx, "/usr/libexec/java_home", "-V")
	if err != nil && len(output) == 0 {
		return nil
	}
	return parseDarwinJavaHomeList(output)
}

// javaHomesFromJetBrains returns Java homes bundled by JetBrains Toolbox and
// standalone JetBrains IDEs. These JDKs are not registered with the system
// `java_home` tool but are used for Maven/Gradle builds launched from inside
// the IDE, which is one of the primary pain points this configurator targets.
func javaHomesFromJetBrains(homeDir string) []string {
	if homeDir == "" {
		return nil
	}
	patterns := []string{
		filepath.Join(homeDir, "Library", "Java", "JavaVirtualMachines", "*", "Contents", "Home"),
		filepath.Join(homeDir, "Library", "Application Support", "JetBrains", "*", "jdks", "*", "Contents", "Home"),
	}
	return globAll(patterns)
}

// javaHomesFromJetBrainsRuntime returns the JetBrains Runtime (JBR) bundled
// inside JetBrains IDE app bundles. Users can pick "Use IDE-bundled JBR" as the
// Gradle JVM, in which case Gradle/Maven builds run in this JDK and need its
// cacerts populated. The /Applications/Toolbox path covers IDEs installed via
// JetBrains Toolbox, which uses sub-bundles per IDE/version.
func javaHomesFromJetBrainsRuntime() []string {
	patterns := []string{
		"/Applications/*.app/Contents/jbr/Contents/Home",
		"/Applications/JetBrains Toolbox/*.app/Contents/jbr/Contents/Home",
	}
	return globAll(patterns)
}

// javaHomesFromHomebrew returns Java homes installed via `brew install openjdk`
// (and its versioned variants). Homebrew does not register these with
// `/usr/libexec/java_home` unless the user runs the optional symlink step, so
// they are otherwise invisible to the standard discovery — yet they are the
// JDKs that back `brew install maven`/`gradle`.
func javaHomesFromHomebrew() []string {
	patterns := []string{
		// Apple Silicon Homebrew prefix
		"/opt/homebrew/Cellar/openjdk*/*/libexec/openjdk.jdk/Contents/Home",
		"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
		// Intel Homebrew prefix
		"/usr/local/Cellar/openjdk*/*/libexec/openjdk.jdk/Contents/Home",
		"/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
	}
	return globAll(patterns)
}

// javaHomesFromVersionManagers returns Java homes managed by sdkman, asdf, and
// jenv. These typically live under the user's home directory and are common
// for developers who juggle multiple JDK versions per project.
func javaHomesFromVersionManagers(homeDir string) []string {
	if homeDir == "" {
		return nil
	}
	patterns := []string{
		filepath.Join(homeDir, ".sdkman", "candidates", "java", "*"),
		filepath.Join(homeDir, ".asdf", "installs", "java", "*"),
		filepath.Join(homeDir, ".jenv", "versions", "*"),
	}
	return globAll(patterns)
}

func globAll(patterns []string) []string {
	var homes []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		homes = append(homes, matches...)
	}
	return homes
}

func parseDarwinJavaHomeList(output string) []string {
	var homes []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		match := darwinJavaHomeRE.FindStringSubmatch(line)
		if len(match) == 2 {
			homes = append(homes, match[1])
		}
	}
	return homes
}

// appendIfMissingCanonicalHome resolves a Java home to its canonical path and
// adds it once. For example, if java_home reports both a symlinked JDK path and
// its real target, we only keep one truststore target.
func appendIfMissingCanonicalHome(homes []string, seen map[string]struct{}, home string) []string {
	canonical := home
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		canonical = resolved
	}
	if _, ok := seen[canonical]; ok {
		return homes
	}
	seen[canonical] = struct{}{}
	return append(homes, canonical)
}

func javaTrustTargetFromHome(home string) (javaTrustTarget, bool) {
	keytoolPath := filepath.Join(home, "bin", "keytool")
	cacertsCandidates := []string{
		filepath.Join(home, "lib", "security", "cacerts"),
		filepath.Join(home, "jre", "lib", "security", "cacerts"),
	}
	if _, err := os.Stat(keytoolPath); err != nil {
		return javaTrustTarget{}, false
	}
	for _, cacertsPath := range cacertsCandidates {
		if _, err := os.Stat(cacertsPath); err == nil {
			return javaTrustTarget{
				javaHome:    home,
				keytoolPath: keytoolPath,
				cacertsPath: cacertsPath,
			}, true
		}
	}
	return javaTrustTarget{}, false
}
