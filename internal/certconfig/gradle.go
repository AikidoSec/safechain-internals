package certconfig

import (
	"context"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type gradleConfigurator struct{}

func newGradleConfigurator() Configurator { return &gradleConfigurator{} }

func (c *gradleConfigurator) Name() string { return "gradle" }

func (c *gradleConfigurator) Install(ctx context.Context) error {
	return installGradleTrust(ctx)
}

func (c *gradleConfigurator) NeedsRepair(_ context.Context) bool {
	if isGradleTrustManaged() {
		return false
	}

	_, err := os.Stat(filepath.Join(platform.GetConfig().HomeDir, ".gradle", "gradle.properties"))
	return err == nil
}

func (c *gradleConfigurator) Uninstall(ctx context.Context) error {
	return uninstallGradleTrust(ctx)
}
