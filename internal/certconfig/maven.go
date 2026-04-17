package certconfig

import (
	"context"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type mavenConfigurator struct{}

func newMavenConfigurator() Configurator { return &mavenConfigurator{} }

func (c *mavenConfigurator) Name() string { return "maven" }

func (c *mavenConfigurator) Install(ctx context.Context) error {
	return installMavenTrust(ctx)
}

func (c *mavenConfigurator) NeedsRepair(_ context.Context) bool {
	if isMavenTrustManaged() {
		return false
	}

	_, err := os.Stat(filepath.Join(platform.GetConfig().HomeDir, ".mavenrc"))
	return err == nil
}

func (c *mavenConfigurator) Uninstall(ctx context.Context) error {
	return uninstallMavenTrust(ctx)
}
