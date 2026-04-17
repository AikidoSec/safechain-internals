//go:build darwin

package certconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const (
	mavenManagedMarkerStart = "# aikido-safe-chain-start"
	mavenManagedMarkerEnd   = "# aikido-safe-chain-end"
)

func installMavenTrust(_ context.Context) error {
	return platform.InstallMavenOptsOverride(platform.GetConfig().HomeDir)
}

func isMavenTrustManaged() bool {
	data, err := os.ReadFile(filepath.Join(platform.GetConfig().HomeDir, ".mavenrc"))
	if err != nil {
		return false
	}

	content := string(data)
	return strings.Contains(content, mavenManagedMarkerStart) && strings.Contains(content, mavenManagedMarkerEnd)
}

func uninstallMavenTrust(_ context.Context) error {
	return platform.UninstallMavenOptsOverride(platform.GetConfig().HomeDir)
}
