//go:build darwin

package certconfig

import (
	"context"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func installGradleTrust(_ context.Context) error {
	return platform.InstallGradleSystemPropsOverride(platform.GetConfig().HomeDir)
}

func uninstallGradleTrust(_ context.Context) error {
	return platform.UninstallGradleSystemPropsOverride(platform.GetConfig().HomeDir)
}
