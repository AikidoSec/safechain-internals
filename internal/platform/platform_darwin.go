//go:build darwin

package platform

import (
	"context"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var networkServices = []string{
	"Wi-Fi",
	"USB 10/100/1000 LAN",
	"Ethernet",
}

func getConfig() *Config {
	return &Config{
		SafeChainBinaryPath: filepath.Join(homeDir, ".safe-chain", "bin", "safe-chain"),
	}
}

func prepareShellEnvironment(_ context.Context) error {
	return nil
}

func setupLogging() (io.Writer, error) {
	return os.Stdout, nil
}

func setSystemProxy(ctx context.Context, proxyURL string) error {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "8080"
	}

	output, err := exec.CommandContext(ctx, "networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return err
	}

	availableServices := string(output)

	for _, service := range networkServices {
		if !strings.Contains(availableServices, service) {
			continue
		}

		if err := exec.CommandContext(ctx, "networksetup", "-setwebproxy", service, host, port).Run(); err != nil {
			return err
		}

		if err := exec.CommandContext(ctx, "networksetup", "-setsecurewebproxy", service, host, port).Run(); err != nil {
			return err
		}
	}

	return nil
}

func unsetSystemProxy(ctx context.Context) error {
	output, err := exec.CommandContext(ctx, "networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return err
	}

	availableServices := string(output)

	for _, service := range networkServices {
		if !strings.Contains(availableServices, service) {
			continue
		}

		if err := exec.CommandContext(ctx, "sudo", "networksetup", "-setwebproxystate", service, "off").Run(); err != nil {
			return err
		}

		if err := exec.CommandContext(ctx, "sudo", "networksetup", "-setsecurewebproxystate", service, "off").Run(); err != nil {
			return err
		}
	}

	return nil
}
