//go:build !darwin

package certconfig

import "context"

type otherGitTrustConfigurator struct{}

func newGitTrustConfigurator(_ string) gitTrustConfigurator {
	return &otherGitTrustConfigurator{}
}

func (c *otherGitTrustConfigurator) Install(_ context.Context) error  { return nil }
func (c *otherGitTrustConfigurator) Uninstall(_ context.Context) error { return nil }

func findSystemGitCABundle() (string, error) { return "", nil }
