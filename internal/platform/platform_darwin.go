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

	"github.com/AikidoSec/safechain-internals/internal/utils"
)

const (
	SafeChainUIBinaryName    = "safechain-ultimate-ui"
	SafeChainProxyBinaryName = "safechain-proxy"
	SafeChainProxyLogName    = "safechain-proxy.log"
	SafeChainProxyErrLogName = "safechain-proxy.err"
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
	config.BinaryDir = "/Library/Application Support/AikidoSecurity/SafeChainUltimate/bin"
	config.RunDir = "/Library/Application Support/AikidoSecurity/SafeChainUltimate/run"
	config.LogDir = "/Library/Logs/AikidoSecurity/SafeChainUltimate"
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

func isProxyEnabledAndUrlSet(output string, proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	port := parsed.Port()
	return strings.Contains(string(output), "Enabled: Yes") && strings.Contains(string(output), "Host: "+host) && strings.Contains(string(output), "Port: "+port)
}

func isPACEnabledAndUrlSet(output string, url string) bool {
	return strings.Contains(string(output), "Enabled: Yes") && strings.Contains(string(output), "URL: "+url)
}

func isSystemProxySetForService(ctx context.Context, service string, proxyURL string) (bool, error) {
	outputHttp, err := exec.CommandContext(ctx, "networksetup", "-getwebproxy", service).Output()
	if err != nil {
		return false, err
	}
	outputHttps, err := exec.CommandContext(ctx, "networksetup", "-getsecurewebproxy", service).Output()
	if err != nil {
		return false, err
	}
	return isProxyEnabledAndUrlSet(string(outputHttp), proxyURL) || isProxyEnabledAndUrlSet(string(outputHttps), proxyURL), nil
}

func isSystemPACSetForService(ctx context.Context, service string, pacURL string) (bool, error) {
	output, err := exec.CommandContext(ctx, "networksetup", "-getautoproxyurl", service).Output()
	if err != nil {
		return false, err
	}
	return isPACEnabledAndUrlSet(string(output), pacURL), nil
}

func setSystemPACForService(ctx context.Context, service string, pacURL string) error {
	errs := []error{}
	if err := exec.CommandContext(ctx, "networksetup", "-setautoproxyurl", service, pacURL).Run(); err != nil {
		errs = append(errs, err)
	}
	if err := exec.CommandContext(ctx, "networksetup", "-setautoproxystate", service, "on").Run(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to set system PAC for service %q: %v", service, errs)
	}
	return nil
}

func unsetSystemPACForService(ctx context.Context, service string) error {
	errs := []error{}
	if err := exec.CommandContext(ctx, "networksetup", "-setautoproxystate", service, "off").Run(); err != nil {
		errs = append(errs, err)
	}
	if err := exec.CommandContext(ctx, "networksetup", "-setautoproxyurl", service, "").Run(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to unset system PAC for service %q: %v", service, errs)
	}
	return nil
}

func SetSystemPAC(ctx context.Context, pacURL string) error {
	services, err := getNetworkServices(ctx)
	if err != nil {
		return err
	}

	for _, service := range services {
		log.Printf("Setting system PAC for service: %q to %q\n", service, pacURL)
		if err := setSystemPACForService(ctx, service, pacURL); err != nil {
			return err
		}
	}

	return nil
}

func IsSystemPACSet(ctx context.Context, pacURL string) error {
	services, err := getNetworkServices(ctx)
	if err != nil {
		return fmt.Errorf("failed to get network services: %v", err)
	}

	servicesWithProxySet := 0
	for _, service := range services {
		set, err := isSystemPACSetForService(ctx, service, pacURL)
		if err != nil {
			return fmt.Errorf("failed to check if system PAC is set for service %q: %v", service, err)
		}
		if set {
			servicesWithProxySet++
		}
	}
	if servicesWithProxySet != len(services) {
		return fmt.Errorf("system proxy is not set correctly for all services")
	}
	return nil
}

func IsAnySystemProxySet(ctx context.Context) (bool, error) {
	services, err := getNetworkServices(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get network services: %v", err)
	}

	proxyCheckFunctions := []func(ctx context.Context, service string, proxyURL string) (bool, error){
		isSystemPACSetForService,
		isSystemProxySetForService,
	}

	for _, service := range services {
		for _, f := range proxyCheckFunctions {
			set, err := f(ctx, service, "")
			if err != nil {
				return false, fmt.Errorf("failed to check if system proxy is set for service %q (possibly not set): %v", service, err)
			}
			if set {
				return true, nil
			}
		}
	}
	return false, nil
}

func UnsetSystemPAC(ctx context.Context, pacURL string) error {
	services, err := getNetworkServices(ctx)
	if err != nil {
		return err
	}

	errs := []error{}
	for _, service := range services {
		log.Println("Unsetting system PAC for service:", service)
		if err := unsetSystemPACForService(ctx, service); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to unset system PAC: %v", errs)
	}
	return nil
}

func InstallProxyCA(ctx context.Context, certPath string) error {
	// CA needs to be installed as current user, in order to be prompted for security permissions
	_, err := RunAsCurrentUser(ctx, "security", []string{"add-trusted-cert",
		"-d", // Add to admin cert store; default is user
		"-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain",
		certPath})
	return err
}

func IsProxyCAInstalled(ctx context.Context) error {
	cmd := exec.CommandContext(ctx,
		"security",
		"find-certificate",
		"-c", "aikidosafechain.com", // Search for certificate with common name "aikidosafechain.com"
		"/Library/Keychains/System.keychain")

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to find certificate: %v", err)
	}
	return nil
}

func UninstallProxyCA(ctx context.Context) error {
	output, err := exec.CommandContext(ctx,
		"security",
		"find-certificate",
		"-a",                        //Find all matching certificates, not just the first one
		"-c", "aikidosafechain.com", // Search for certificate with common name "aikidosafechain.com"
		"-Z", // Print SHA-256 (and SHA-1) hash of the certificate
		"/Library/Keychains/System.keychain").Output()

	errs := []error{}
	if err == nil {
		hashRegex := regexp.MustCompile(`SHA-1 hash:\s*([A-F0-9]+)`)
		matches := hashRegex.FindAllStringSubmatch(string(output), -1)

		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			hash := match[1]
			_, err := RunAsCurrentUser(ctx, "security", []string{"delete-certificate",
				"-Z", hash,
				"/Library/Keychains/System.keychain"})
			if err != nil {
				errs = append(errs, err)
			}
		}
	}

	if _, err := RunAsCurrentUser(ctx, "security", []string{"delete-generic-password",
		"-l", "tls-root-ca-key",
		"/Library/Keychains/System.keychain"}); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to uninstall proxy CA: %v", errs)
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

func RunAsCurrentUser(ctx context.Context, binaryPath string, args []string) (string, error) {
	if !RunningAsRoot() {
		return utils.RunCommand(ctx, binaryPath, args...)
	}

	username, uid, err := getConsoleUser(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get console user: %v", err)
	}

	homeDir := filepath.Join("/Users", username)
	launchctlArgs := append([]string{"asuser", uid, binaryPath}, args...)
	return utils.RunCommandWithEnv(ctx, []string{fmt.Sprintf("HOME=%s", homeDir)}, "launchctl", launchctlArgs...)
}

func RunningAsRoot() bool {
	return os.Getuid() == 0
}

func InstallSafeChain(ctx context.Context, repoURL, version string) error {
	scriptURL := fmt.Sprintf("%s/releases/download/%s/install-safe-chain.sh", repoURL, version)
	scriptPath := filepath.Join(os.TempDir(), "install-safe-chain.sh")

	log.Printf("Downloading install script from %s...", scriptURL)
	if err := utils.DownloadBinary(ctx, scriptURL, scriptPath); err != nil {
		return fmt.Errorf("failed to download install script: %w", err)
	}
	defer os.Remove(scriptPath)
	if _, err := RunAsCurrentUser(ctx, "sh", []string{scriptPath}); err != nil {
		return fmt.Errorf("failed to run uninstall script: %w", err)
	}
	return nil
}

func UninstallSafeChain(ctx context.Context, repoURL, version string) error {
	scriptURL := fmt.Sprintf("%s/releases/download/%s/uninstall-safe-chain.sh", repoURL, version)
	scriptPath := filepath.Join(os.TempDir(), "uninstall-safe-chain.sh")

	log.Printf("Downloading uninstall script from %s...", scriptURL)
	if err := utils.DownloadBinary(ctx, scriptURL, scriptPath); err != nil {
		return fmt.Errorf("failed to download uninstall script: %w", err)
	}
	defer os.Remove(scriptPath)

	if _, err := RunAsCurrentUser(ctx, "sh", []string{scriptPath}); err != nil {
		return fmt.Errorf("failed to run uninstall script: %w", err)
	}
	return nil
}
