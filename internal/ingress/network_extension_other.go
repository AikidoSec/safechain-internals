//go:build !darwin

package ingress

import (
	"context"
	"fmt"
)

func activateNetworkExtension(_ context.Context) (string, error) {
	return "", fmt.Errorf("network extension is only supported on macOS")
}

func openNetworkExtensionSettings(_ context.Context) error {
	return fmt.Errorf("network extension is only supported on macOS")
}

func IsNetworkExtensionActivated(_ context.Context) (bool, error) {
	return false, fmt.Errorf("network extension is only supported on macOS")
}

func IsNetworkExtensionVpnAllowed(_ context.Context) (bool, error) {
	return false, fmt.Errorf("network extension is only supported on macOS")
}

func allowNetworkExtensionVpn(_ context.Context) (string, error) {
	return "", fmt.Errorf("network extension is only supported on macOS")
}
