//go:build darwin

package ingress

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func activateNetworkExtension(ctx context.Context) (string, error) {
	output, err := platform.RunInAuditSessionOfCurrentUser(ctx, platform.SafeChainL4ProxyHostPath, []string{"activate-extension"})
	outputStr := strings.TrimSpace(output)
	log.Printf("network extension activate output: %s", outputStr)

	if strings.HasPrefix(outputStr, "extension: ") {
		return strings.TrimPrefix(outputStr, "extension: "), nil
	}
	if err != nil {
		return "", fmt.Errorf("activate-extension failed: %w", err)
	}
	return "", fmt.Errorf("unexpected activate-extension output: %s", outputStr)
}

func openNetworkExtensionSettings(ctx context.Context) error {
	_, err := platform.RunInAuditSessionOfCurrentUser(ctx, "/usr/bin/open", []string{"x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point"})
	return err
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
