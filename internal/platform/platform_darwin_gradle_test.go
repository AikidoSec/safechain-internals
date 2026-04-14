//go:build darwin

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallGradleSystemPropsOverrideCreatesManagedBlock(t *testing.T) {
	homeDir := t.TempDir()

	if err := InstallGradleSystemPropsOverride(homeDir); err != nil {
		t.Fatalf("InstallGradleSystemPropsOverride failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(homeDir, ".gradle", "gradle.properties"))
	if err != nil {
		t.Fatalf("failed to read gradle.properties: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, gradlePropsMarkerStart) {
		t.Fatalf("expected managed Gradle block, got %q", content)
	}
	if !strings.Contains(content, "systemProp.javax.net.ssl.trustStoreType=KeychainStore") {
		t.Fatalf("expected trustStoreType override, got %q", content)
	}
	if !strings.Contains(content, "systemProp.javax.net.ssl.trustStore=NONE") {
		t.Fatalf("expected trustStore override, got %q", content)
	}
}

func TestInstallGradleSystemPropsOverridePreservesExistingContent(t *testing.T) {
	homeDir := t.TempDir()
	propsPath := filepath.Join(homeDir, ".gradle", "gradle.properties")
	if err := os.MkdirAll(filepath.Dir(propsPath), 0o755); err != nil {
		t.Fatal(err)
	}

	initial := "org.gradle.parallel=true\n"
	if err := os.WriteFile(propsPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := InstallGradleSystemPropsOverride(homeDir); err != nil {
		t.Fatalf("InstallGradleSystemPropsOverride failed: %v", err)
	}

	data, err := os.ReadFile(propsPath)
	if err != nil {
		t.Fatalf("failed to read gradle.properties: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, initial) {
		t.Fatalf("expected existing Gradle properties to be preserved, got %q", content)
	}

	if err := InstallGradleSystemPropsOverride(homeDir); err != nil {
		t.Fatalf("second InstallGradleSystemPropsOverride failed: %v", err)
	}

	data, err = os.ReadFile(propsPath)
	if err != nil {
		t.Fatalf("failed to reread gradle.properties: %v", err)
	}
	if got := strings.Count(string(data), gradlePropsMarkerStart); got != 1 {
		t.Fatalf("expected one managed Gradle block, got %d in %q", got, string(data))
	}
}

func TestUninstallGradleSystemPropsOverrideRemovesOnlyManagedBlock(t *testing.T) {
	homeDir := t.TempDir()
	propsPath := filepath.Join(homeDir, ".gradle", "gradle.properties")
	if err := os.MkdirAll(filepath.Dir(propsPath), 0o755); err != nil {
		t.Fatal(err)
	}

	initial := "org.gradle.parallel=true\n"
	if err := os.WriteFile(propsPath, []byte(initial+gradlePropsBlock), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := UninstallGradleSystemPropsOverride(homeDir); err != nil {
		t.Fatalf("UninstallGradleSystemPropsOverride failed: %v", err)
	}

	data, err := os.ReadFile(propsPath)
	if err != nil {
		t.Fatalf("failed to read gradle.properties: %v", err)
	}

	content := string(data)
	if strings.Contains(content, gradlePropsMarkerStart) {
		t.Fatalf("expected managed Gradle block removed, got %q", content)
	}
	if !strings.Contains(content, initial) {
		t.Fatalf("expected unmanaged content preserved, got %q", content)
	}
}
