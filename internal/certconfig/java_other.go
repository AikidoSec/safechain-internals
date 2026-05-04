//go:build !darwin && !windows

package certconfig

import "context"

func installJavaTrust(_ context.Context) error   { return nil }
func javaNeedsRepair(_ context.Context) bool     { return false }
func uninstallJavaTrust(_ context.Context) error { return nil }
