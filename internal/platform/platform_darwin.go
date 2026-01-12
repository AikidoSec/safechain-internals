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
	"regexp"
	"strings"

	"github.com/AikidoSec/safechain-agent/internal/utils"
)

const (
	SafeChainProxyBinaryName = "safechain-proxy"
	SafeChainProxyLogName    = "safechain-proxy.log"
)

var serviceRegex = regexp.MustCompile(`^\((\d+)\)\s+(.+)$`)
var deviceRegex = regexp.MustCompile(`Device:\s*(en\d+)`)

func initConfig() error {
	if RunningAsRoot() {
		username, _, err := getConsoleUser(context.Background())
		if err != nil {
			return fmt.Errorf("failed to get console user: %v", err)
		}
		config.HomeDir = filepath.Join("/Users", username)
	} else {
		var err error
		config.HomeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %v", err)
		}
	}
	safeChainHomeDir := filepath.Join(config.HomeDir, ".safe-chain")
	config.BinaryDir = "/opt/homebrew/bin"
	config.RunDir = filepath.Join(safeChainHomeDir, "run")
	config.LogDir = filepath.Join(safeChainHomeDir, "logs")
	config.SafeChainBinaryPath = filepath.Join(safeChainHomeDir, "bin", "safe-chain")
	return nil
}

func PrepareShellEnvironment(_ context.Context) error {
	return nil
}

func SetupLogging() (io.Writer, error) {
	return os.Stdout, nil
}

/*
This function returns the list of network services on the system.
It identifies the services that are currently active and have a physical network interface.
Examples of services are: "Wi-Fi", "LAN", ...
*/
func getNetworkServices(ctx context.Context) ([]string, error) {
	output, err := exec.CommandContext(ctx, "networksetup", "-listnetworkserviceorder").Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var services []string
	var currentService string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			continue
		}
		if match := serviceRegex.FindStringSubmatch(line); match != nil {
			currentService = match[2]
			continue
		}
		if currentService != "" && deviceRegex.MatchString(line) {
			services = append(services, currentService)
			currentService = ""
		}
	}
	return services, nil
}

func SetSystemProxy(ctx context.Context, proxyURL string) error {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		return fmt.Errorf("port is required")
	}

	services, err := getNetworkServices(ctx)
	if err != nil {
		return err
	}

	for _, service := range services {
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

func IsSystemProxySet(ctx context.Context, proxyURL string) error {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		return fmt.Errorf("port is required")
	}

	services, err := getNetworkServices(ctx)
	if err != nil {
		return fmt.Errorf("failed to get network services: %v", err)
	}

	servicesWithProxySet := 0
	for _, service := range services {
		output, err := exec.CommandContext(ctx, "networksetup", "-getwebproxy", service).Output()
		if err != nil {
			continue
		}
		if strings.Contains(string(output), "Enabled: Yes") &&
			strings.Contains(string(output), "Server: "+host) &&
			strings.Contains(string(output), "Port: "+port) {
			servicesWithProxySet += 1
		}
	}
	if servicesWithProxySet != len(services) {
		return fmt.Errorf("system proxy is not set correctly for all services")
	}
	return nil
}

func UnsetSystemProxy(ctx context.Context) error {
	services, err := getNetworkServices(ctx)
	if err != nil {
		return err
	}
	for _, service := range services {
		log.Println("Unsetting system proxy for service:", service)

		if err := exec.CommandContext(ctx, "networksetup", "-setwebproxystate", service, "off").Run(); err != nil {
			return err
		}

		if err := exec.CommandContext(ctx, "networksetup", "-setsecurewebproxystate", service, "off").Run(); err != nil {
			return err
		}
	}

	return nil
}

func InstallProxyCA(ctx context.Context, certPath string) error {
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

func IsProxyCAInstalled(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "security", "find-certificate",
		"-c", "aikido.dev",
		"/Library/Keychains/System.keychain")

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to find certificate: %v", err)
	}
	return nil
}

func UninstallProxyCA(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "security", "delete-certificate",
		"-c", "aikido.dev",
		"/Library/Keychains/System.keychain")

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to delete certificate: %v", err)
	}
	return nil
}

type ServiceRunner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

func IsWindowsService() bool {
	return false
}

func RunAsWindowsService(runner ServiceRunner, serviceName string) error {
	return nil
}

func getConsoleUser(ctx context.Context) (string, string, error) {
	output, err := exec.CommandContext(ctx, "stat", "-f", "%Su %u", "/dev/console").Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to get console user: %v", err)
	}
	parts := strings.Fields(string(output))
	if len(parts) != 2 {
		return "", "", fmt.Errorf("unexpected stat output: %s", output)
	}
	username, uid := parts[0], parts[1]
	if username == "" || username == "root" {
		return "", "", fmt.Errorf("no interactive user logged in")
	}
	return username, uid, nil
}

func RunAsCurrentUser(ctx context.Context, binaryPath string, args []string) error {
	if !RunningAsRoot() {
		return utils.RunCommand(ctx, binaryPath, args...)
	}

	_, uid, err := getConsoleUser(ctx)
	if err != nil {
		return err
	}

	// launchtl asuser 123 <binary_path> args...
	launchctlArgs := append([]string{"asuser", uid, binaryPath}, args...)
	return utils.RunCommand(ctx, "launchctl", launchctlArgs...)
}

func RunningAsRoot() bool {
	return os.Getuid() == 0
}
