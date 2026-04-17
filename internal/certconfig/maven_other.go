//go:build !darwin

package certconfig

import "context"

func installMavenTrust(_ context.Context) error   { return nil }
func isMavenTrustManaged() bool                   { return false }
func uninstallMavenTrust(_ context.Context) error { return nil }
