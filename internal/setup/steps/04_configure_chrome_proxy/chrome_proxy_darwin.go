//go:build darwin

package configure_chrome_proxy

import (
	"context"
	"fmt"
	"os/exec"
)

// chromePolicyDomain is the managed preferences domain for Google Chrome.
// Writing to /Library/Managed Preferences/<domain>.plist requires root.
const chromePolicyDomain = "com.google.Chrome"
const chromePolicyPlist = "/Library/Managed Preferences/" + chromePolicyDomain + ".plist"

func installChromeProxy(_ context.Context, pacURL string) error {
	// Write only the ProxySettings key, leaving any existing managed policies untouched.
	// `defaults write` creates the plist if absent, or merges into an existing one.
	if err := exec.Command("defaults", "write", chromePolicyPlist,
		"ProxySettings",
		"-dict",
		"ProxyMode", "pac_script",
		"ProxyPacUrl", pacURL,
	).Run(); err != nil {
		return fmt.Errorf("write Chrome ProxySettings policy: %w", err)
	}

	return nil
}

func uninstallChromeProxy(_ context.Context) error {
	// Remove only the ProxySettings key we own; leave other managed policies intact.
	// `defaults delete` exits 1 when the key doesn't exist — that's fine.
	_ = exec.Command("defaults", "delete", chromePolicyPlist, "ProxySettings").Run()
	return nil
}
