package certconfig

import "context"

type gitTrustConfigurator interface {
	Install(context.Context) error
	Uninstall(context.Context) error
}

type gitConfigurator struct {
	trust gitTrustConfigurator
}

func newGitConfigurator() Configurator {
	return &gitConfigurator{
		trust: newGitTrustConfigurator(systemCombinedCaBundlePath()),
	}
}

func (c *gitConfigurator) Name() string { return "git" }

func (c *gitConfigurator) Install(ctx context.Context) error {
	return c.trust.Install(ctx)
}

func (c *gitConfigurator) Uninstall(ctx context.Context) error {
	return c.trust.Uninstall(ctx)
}
