//go:build darwin

package certconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func TestInstallGradleTrustCreatesManagedBlock(t *testing.T) {
	homeDir := t.TempDir()
	platform.GetConfig().HomeDir = homeDir

	if err := installGradleTrust(t.Context()); err != nil {
		t.Fatalf("installGradleTrust failed: %v", err)
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

func TestInstallGradleTrustPreservesExistingContent(t *testing.T) {
	homeDir := t.TempDir()
	platform.GetConfig().HomeDir = homeDir

	propsPath := filepath.Join(homeDir, ".gradle", "gradle.properties")
	if err := os.MkdirAll(filepath.Dir(propsPath), 0o755); err != nil {
		t.Fatal(err)
	}

	initial := "org.gradle.parallel=true\n"
	if err := os.WriteFile(propsPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := installGradleTrust(t.Context()); err != nil {
		t.Fatalf("installGradleTrust failed: %v", err)
	}

	data, err := os.ReadFile(propsPath)
	if err != nil {
		t.Fatalf("failed to read gradle.properties: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, initial) {
		t.Fatalf("expected existing Gradle properties to be preserved, got %q", content)
	}

	if err := installGradleTrust(t.Context()); err != nil {
		t.Fatalf("second installGradleTrust failed: %v", err)
	}

	data, err = os.ReadFile(propsPath)
	if err != nil {
		t.Fatalf("failed to reread gradle.properties: %v", err)
	}
	if got := strings.Count(string(data), gradlePropsMarkerStart); got != 1 {
		t.Fatalf("expected one managed Gradle block, got %d in %q", got, string(data))
	}
}

func TestUninstallGradleTrustRemovesOnlyManagedBlock(t *testing.T) {
	homeDir := t.TempDir()
	platform.GetConfig().HomeDir = homeDir

	propsPath := filepath.Join(homeDir, ".gradle", "gradle.properties")
	if err := os.MkdirAll(filepath.Dir(propsPath), 0o755); err != nil {
		t.Fatal(err)
	}

	initial := "org.gradle.parallel=true\n"
	if err := os.WriteFile(propsPath, []byte(initial+gradlePropsBlock), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := uninstallGradleTrust(t.Context()); err != nil {
		t.Fatalf("uninstallGradleTrust failed: %v", err)
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

func TestGradleConfiguratorNeedsRepairWhenManagedBlockMissing(t *testing.T) {
	homeDir := t.TempDir()
	platform.GetConfig().HomeDir = homeDir

	propsPath := filepath.Join(homeDir, ".gradle", "gradle.properties")
	if err := os.MkdirAll(filepath.Dir(propsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(propsPath, []byte("org.gradle.parallel=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !newGradleConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected Gradle trust repair to be required when managed block is missing")
	}
}

func TestGradleConfiguratorNeedsRepairFalseWhenManagedBlockPresent(t *testing.T) {
	homeDir := t.TempDir()
	platform.GetConfig().HomeDir = homeDir

	if err := installGradleTrust(t.Context()); err != nil {
		t.Fatalf("installGradleTrust failed: %v", err)
	}

	if newGradleConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected Gradle trust to be healthy when managed block is present")
	}
}
