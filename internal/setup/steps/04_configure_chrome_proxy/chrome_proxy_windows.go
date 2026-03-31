//go:build windows

package configure_chrome_proxy

import "context"

func installChromeProxy(_ context.Context, _ string) error  { return nil }
func uninstallChromeProxy(_ context.Context) error          { return nil }
