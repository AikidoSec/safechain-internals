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
		deleteJavaTrustAlias(ctx, target)
	}
	return nil
}

func syncJavaTrustTarget(ctx context.Context, target javaTrustTarget, caPath string) error {
	// keytool has no upsert, so we delete-then-import. The delete is best-effort:
	// if it fails (alias absent on a fresh JDK, or any other reason), the import
	// below is the ground truth and will surface real problems.
	deleteJavaTrustAlias(ctx, target)

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

// deleteJavaTrustAlias is best-effort. Callers never act on the outcome:
// install re-imports either way, uninstall is teardown. Errors are logged at
// debug granularity — the "alias absent" case is the dominant one and not
// worth classifying.
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
