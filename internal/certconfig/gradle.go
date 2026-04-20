package certconfig

import "context"

type gradleConfigurator struct{}

func newGradleConfigurator() Configurator { return &gradleConfigurator{} }

func (c *gradleConfigurator) Name() string { return "gradle" }

func (c *gradleConfigurator) Install(ctx context.Context) error {
	return installGradleTrust(ctx)
}

func (c *gradleConfigurator) Uninstall(ctx context.Context) error {
	return uninstallGradleTrust(ctx)
}
