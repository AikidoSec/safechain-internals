//go:build !darwin

package certconfig

import "context"

func installGradleTrust(_ context.Context) error { return nil }

func isGradleTrustManaged() bool { return false }

func uninstallGradleTrust(_ context.Context) error { return nil }
