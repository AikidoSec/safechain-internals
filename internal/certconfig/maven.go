package certconfig

import "context"

type mavenConfigurator struct{}

func newMavenConfigurator() Configurator { return &mavenConfigurator{} }

func (c *mavenConfigurator) Name() string { return "maven" }

func (c *mavenConfigurator) Install(ctx context.Context) error {
	return installMavenTrust(ctx)
}

func (c *mavenConfigurator) Uninstall(ctx context.Context) error {
	return uninstallMavenTrust(ctx)
}
