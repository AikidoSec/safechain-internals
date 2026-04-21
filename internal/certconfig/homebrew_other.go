//go:build !darwin

package certconfig

import "context"

type homebrewConfigurator struct{}

func newHomebrewConfigurator() Configurator { return &homebrewConfigurator{} }

func (c *homebrewConfigurator) Name() string { return "homebrew" }

func (c *homebrewConfigurator) Install(_ context.Context) error    { return nil }
func (c *homebrewConfigurator) NeedsRepair(_ context.Context) bool { return false }
func (c *homebrewConfigurator) Uninstall(_ context.Context) error  { return nil }
