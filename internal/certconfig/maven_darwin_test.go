//go:build darwin

package certconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func TestMavenConfiguratorNeedsRepairWhenManagedBlockMissing(t *testing.T) {
	homeDir := t.TempDir()
	platform.GetConfig().HomeDir = homeDir

	mavenrcPath := filepath.Join(homeDir, ".mavenrc")
	if err := os.WriteFile(mavenrcPath, []byte("export MAVEN_OPTS=\"-Xmx512m\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !newMavenConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected Maven trust repair to be required when managed block is missing")
	}
}

func TestMavenConfiguratorNeedsRepairFalseWhenManagedBlockPresent(t *testing.T) {
	homeDir := t.TempDir()
	platform.GetConfig().HomeDir = homeDir

	if err := platform.InstallMavenOptsOverride(homeDir); err != nil {
		t.Fatalf("InstallMavenOptsOverride failed: %v", err)
	}

	if newMavenConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected Maven trust to be healthy when managed block is present")
	}
}
