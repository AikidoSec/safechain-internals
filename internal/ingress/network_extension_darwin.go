//go:build darwin

package ingress

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func installNetworkExtension(ctx context.Context) (string, error) {
	output, err := platform.RunInAuditSessionOfCurrentUser(ctx, platform.SafeChainL4ProxyHostPath, []string{"install-extension"})
	outputStr := strings.TrimSpace(output)
	log.Printf("network extension install output: %s", outputStr)

	if strings.HasPrefix(outputStr, "extension: ") {
		return strings.TrimPrefix(outputStr, "extension: "), nil
	}
	if err != nil {
		return "", fmt.Errorf("install-extension failed: %w", err)
	}
	return "", fmt.Errorf("unexpected install-extension output: %s", outputStr)
}

func openNetworkExtensionSettings(ctx context.Context) error {
	_, err := platform.RunInAuditSessionOfCurrentUser(ctx, "/usr/bin/open", []string{"x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point"})
	return err
}

func IsNetworkExtensionInstalled(ctx context.Context) (bool, error) {
	output, err := platform.RunInAuditSessionOfCurrentUser(ctx, platform.SafeChainL4ProxyHostPath, []string{"is-extension-installed"})
	outputStr := strings.TrimSpace(output)
	log.Printf("network extension is-extension-installed output: %s", outputStr)

	if outputStr == "extension-installed: true" {
		return true, nil
	}
	if outputStr == "extension-installed: false" {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is-extension-installed failed: %w", err)
	}
	return false, fmt.Errorf("unexpected is-extension-installed output: %s", outputStr)
}

func IsNetworkExtensionActivated(ctx context.Context) (bool, error) {
	output, err := platform.RunInAuditSessionOfCurrentUser(ctx, platform.SafeChainL4ProxyHostPath, []string{"is-extension-activated"})
	outputStr := strings.TrimSpace(output)
	log.Printf("network extension is-extension-activated output: %s", outputStr)

	if outputStr == "extension-activated: true" {
		return true, nil
	}
	if outputStr == "extension-activated: false" {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is-extension-activated failed: %w", err)
	}
	return false, fmt.Errorf("unexpected is-extension-activated output: %s", outputStr)
}

func IsNetworkExtensionVpnAllowed(ctx context.Context) (bool, error) {
	output, err := platform.RunInAuditSessionOfCurrentUser(ctx, platform.SafeChainL4ProxyHostPath, []string{"is-vpn-allowed"})
	outputStr := strings.TrimSpace(output)
	log.Printf("network extension is-vpn-allowed output: %s", outputStr)

	if outputStr == "vpn-allowed: true" {
		return true, nil
	}
	if outputStr == "vpn-allowed: false" {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is-vpn-allowed failed: %w", err)
	}
	return false, fmt.Errorf("unexpected is-vpn-allowed output: %s", outputStr)
}

func allowNetworkExtensionVpn(ctx context.Context) (string, error) {
	output, err := platform.RunInAuditSessionOfCurrentUser(ctx, platform.SafeChainL4ProxyHostPath, []string{"allow-vpn"})
	outputStr := strings.TrimSpace(output)
	log.Printf("network extension allow-vpn output: %s", outputStr)

	if strings.HasPrefix(outputStr, "vpn: ") {
		return strings.TrimPrefix(outputStr, "vpn: "), nil
	}
	if err != nil {
		return "", fmt.Errorf("allow-vpn failed: %w", err)
	}
	return "", fmt.Errorf("unexpected allow-vpn output: %s", outputStr)
}
