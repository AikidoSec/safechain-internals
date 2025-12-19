//go:build darwin

package platform

import (
	"context"
	"fmt"
	"io"
	"log"
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
		BinaryDir:           "/opt/homebrew/bin",
		RunDir:              "/opt/homebrew/var/run/",
		LogDir:              "/opt/homebrew/var/log/",
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
		return fmt.Errorf("port is required")
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

		log.Printf("Setting system proxy for service: %q to %q\n", service, proxyURL)

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

		log.Println("Unsetting system proxy for service:", service)

		if err := exec.CommandContext(ctx, "sudo", "networksetup", "-setwebproxystate", service, "off").Run(); err != nil {
			return err
		}

		if err := exec.CommandContext(ctx, "sudo", "networksetup", "-setsecurewebproxystate", service, "off").Run(); err != nil {
			return err
		}
	}

	return nil
}

func installProxyCA(ctx context.Context, certPath string) error {
	cmd := exec.CommandContext(ctx, "security", "add-trusted-cert",
		"-d",
		"-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain",
		certPath)

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add trusted certificate: %v", err)
	}
	return nil
}

func checkProxyCA(ctx context.Context, certPath string) error {
	cmd := exec.CommandContext(ctx, "security", "find-certificate",
		"-c", "aikido.dev",
		"/Library/Keychains/System.keychain")

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to check certificate installation: %v", err)
	}
	return nil
}

func uninstallProxyCA(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "security", "delete-certificate",
		"-c", "aikido.dev",
		"/Library/Keychains/System.keychain")

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to delete certificate: %v", err)
	}
	return nil
}
