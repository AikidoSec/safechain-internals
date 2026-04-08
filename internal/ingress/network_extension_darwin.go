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
