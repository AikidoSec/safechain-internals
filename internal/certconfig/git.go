package certconfig

import "context"

type gitTrustConfigurator interface {
	Install(context.Context) error
	Uninstall(context.Context) error
	NeedsRepair(context.Context) bool
}

type gitConfigurator struct {
	trust gitTrustConfigurator
}

func newGitConfigurator() Configurator {
	return &gitConfigurator{
		trust: newGitTrustConfigurator(gitCombinedCaBundlePath()),
	}
}

func (c *gitConfigurator) Name() string { return "git" }

func (c *gitConfigurator) Install(ctx context.Context) error {
	return c.trust.Install(ctx)
}

func (c *gitConfigurator) NeedsRepair(ctx context.Context) bool {
	return c.trust.NeedsRepair(ctx)
}

func (c *gitConfigurator) Uninstall(ctx context.Context) error {
	return c.trust.Uninstall(ctx)
}
