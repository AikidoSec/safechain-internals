package certconfig

import "context"

type nodeTrustConfigurator interface {
	Install(context.Context) error
	Uninstall(context.Context) error
}

type nodeConfigurator struct {
	trust nodeTrustConfigurator
}

func newNodeConfigurator() Configurator {
	return &nodeConfigurator{
		trust: newNodeTrustConfigurator(combinedCaBundlePath()),
	}
}

func (c *nodeConfigurator) Name() string {
	return "node"
}

func (c *nodeConfigurator) Install(ctx context.Context) error {
	if _, err := ensureCombinedCABundle(ctx); err != nil {
		return err
	}
	return c.trust.Install(ctx)
}

func (c *nodeConfigurator) Uninstall(ctx context.Context) error {
	if err := c.trust.Uninstall(ctx); err != nil {
		return err
	}
	return removeCombinedCABundle()
}
