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

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

const javaTrustAlias = "aikido-safechain-proxy-ca"

var darwinJavaHomeRE = regexp.MustCompile(`(/.*(?:/Contents/Home|/Home))\s*$`)

type javaTrustTarget struct {
	javaHome    string
	keytoolPath string
	cacertsPath string
}

func installJavaTrust(ctx context.Context) error {
	targets := darwinJavaTrustTargets(ctx)
	if len(targets) == 0 {
		return nil
	}

	caPath := proxy.GetCaCertPath()
	if _, err := os.Stat(caPath); err != nil {
		return fmt.Errorf("java: failed to stat downloaded proxy CA %s: %w", caPath, err)
	}

	var errs []error
	for _, target := range targets {
		if err := syncJavaTrustTarget(ctx, target, caPath); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("java: failed to sync truststore entries: %v", errs)
	}
	return nil
}

func javaNeedsRepair(ctx context.Context) bool {
	targets := darwinJavaTrustTargets(ctx)
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		present, err := javaTrustAliasPresent(ctx, target)
		if err != nil {
			log.Printf("java: failed to inspect truststore %s: %v", target.cacertsPath, err)
			return true
		}
		if !present {
			return true
		}
	}
	return false
}

func uninstallJavaTrust(ctx context.Context) error {
	targets := darwinJavaTrustTargets(ctx)

	var errs []error
	for _, target := range targets {
		if err := deleteJavaTrustAlias(ctx, target); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("java: failed to remove truststore entries: %v", errs)
	}
	return nil
}

func syncJavaTrustTarget(ctx context.Context, target javaTrustTarget, caPath string) error {
	if err := deleteJavaTrustAlias(ctx, target); err != nil {
		return err
	}

	output, err := platform.RunAsCurrentUserWithPathEnv(ctx,
		target.keytoolPath,
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

func deleteJavaTrustAlias(ctx context.Context, target javaTrustTarget) error {
	output, err := platform.RunAsCurrentUserWithPathEnv(ctx,
		target.keytoolPath,
		"-delete",
		"-alias", javaTrustAlias,
		"-keystore", target.cacertsPath,
		"-storepass", "changeit",
	)
	if err == nil {
		return nil
	}

	trimmed := strings.TrimSpace(output)
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "does not exist") || strings.Contains(lower, "alias") && strings.Contains(lower, "not exist") {
		return nil
	}
	return fmt.Errorf("java: keytool delete failed for %s: %w (output: %s)", target.cacertsPath, err, trimmed)
}

func javaTrustAliasPresent(ctx context.Context, target javaTrustTarget) (bool, error) {
	output, err := platform.RunAsCurrentUserWithPathEnv(ctx,
		target.keytoolPath,
		"-list",
		"-alias", javaTrustAlias,
		"-keystore", target.cacertsPath,
		"-storepass", "changeit",
	)
	if err == nil {
		return true, nil
	}

	lower := strings.ToLower(strings.TrimSpace(output))
	if strings.Contains(lower, "does not exist") || strings.Contains(lower, "alias") && strings.Contains(lower, "not exist") {
		return false, nil
	}
	return false, fmt.Errorf("keytool list failed: %w (output: %s)", err, strings.TrimSpace(output))
}

func darwinJavaTrustTargets(ctx context.Context) []javaTrustTarget {
	seen := map[string]struct{}{}
	var homes []string

	for _, home := range javaHomesFromJavaHomeTool(ctx) {
		homes = appendIfMissingCanonicalHome(homes, seen, home)
	}

	targets := make([]javaTrustTarget, 0, len(homes))
	for _, home := range homes {
		target, ok := javaTrustTargetFromHome(home)
		if ok {
			targets = append(targets, target)
		}
	}
	return targets
}

func javaHomesFromJavaHomeTool(ctx context.Context) []string {
	output, err := platform.RunAsCurrentUserWithPathEnv(ctx, "/usr/libexec/java_home", "-V")
	if err != nil && len(output) == 0 {
		return nil
	}
	return parseDarwinJavaHomeList(output)
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
