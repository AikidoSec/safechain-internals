package certconfig

import "context"

type javaConfigurator struct{}

func newJavaConfigurator() Configurator { return &javaConfigurator{} }

func (c *javaConfigurator) Name() string { return "java" }

func (c *javaConfigurator) Install(ctx context.Context) error {
	return installJavaTrust(ctx)
}

func (c *javaConfigurator) NeedsRepair(ctx context.Context) bool {
	return javaNeedsRepair(ctx)
}

func (c *javaConfigurator) Uninstall(ctx context.Context) error {
	return uninstallJavaTrust(ctx)
}
