//go:build darwin

package certconfig

import (
	"context"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const (
	mavenManagedMarkerStart = "# aikido-safe-chain-start"
	mavenManagedMarkerEnd   = "# aikido-safe-chain-end"
)

var mavenManagedBlockFormat = managedBlockFormat{
	startMarker: mavenManagedMarkerStart,
	endMarker:   mavenManagedMarkerEnd,
}

func installMavenTrust(_ context.Context) error {
	return platform.InstallMavenOptsOverride(platform.GetConfig().HomeDir)
}

func isMavenTrustManaged() bool {
	present, _ := hasManagedBlock(filepath.Join(platform.GetConfig().HomeDir, ".mavenrc"), mavenManagedBlockFormat)
	return present
}

func mavenNeedsRepair() bool {
	if isMavenTrustManaged() {
		return false
	}
	_, err := os.Stat(filepath.Join(platform.GetConfig().HomeDir, ".mavenrc"))
	return err == nil
}

func uninstallMavenTrust(_ context.Context) error {
	return platform.UninstallMavenOptsOverride(platform.GetConfig().HomeDir)
}
