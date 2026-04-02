//go:build !darwin

package certconfig

import "context"

func installMavenTrust(_ context.Context) error   { return nil }
func uninstallMavenTrust(_ context.Context) error { return nil }
