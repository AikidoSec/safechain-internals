package certconfig

import (
	"context"
	"fmt"
)

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
	baseCACertBundle, err := findSystemGitCABundle()
	if err != nil {
		return fmt.Errorf("git: could not find system CA bundle: %w", err)
	}
	if baseCACertBundle == "" {
		return fmt.Errorf("git: no system CA bundle found")
	}
	if _, err := ensureSystemCombinedCABundle(baseCACertBundle); err != nil {
		return err
	}
	return c.trust.Install(ctx)
}

func (c *gitConfigurator) Uninstall(ctx context.Context) error {
	if err := c.trust.Uninstall(ctx); err != nil {
		return err
	}
	return removeSystemCombinedCABundle()
}
