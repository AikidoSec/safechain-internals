//go:build darwin

package certconfig

import (
	"context"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func installMavenTrust(_ context.Context) error {
	return platform.InstallMavenOptsOverride(platform.GetConfig().HomeDir)
}

func uninstallMavenTrust(_ context.Context) error {
	return platform.UninstallMavenOptsOverride(platform.GetConfig().HomeDir)
}
