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
	"strconv"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/utils"
	"golang.org/x/sys/unix"
)

const (
	SafeChainUltimateLogName     = "safechain-ultimate.log"
	SafeChainUltimateErrLogName  = "safechain-ultimate.error.log"
	SafeChainUIAppName           = "safechain-ultimate-ui.app/Contents/MacOS/safechain-ultimate-ui"
	SafeChainL7ProxyBinaryName   = "safechain-l7-proxy"
	SafeChainL7ProxyLogName      = "safechain-l7-proxy.log"
	SafeChainL7ProxyErrLogName   = "safechain-l7-proxy.err"
	SafeChainInstallScriptName   = "install-safe-chain.sh"
	SafeChainUninstallScriptName = "uninstall-safe-chain.sh"
)

var serviceRegex = regexp.MustCompile(`^\((\d+)\)\s+(.+)$`)
var deviceRegex = regexp.MustCompile(`Device:\s*(en\d+)`)

func initConfig() error {
	if RunningAsRoot() {
		username, _, _, _, err := GetCurrentUser(context.Background())
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
	_, err := RunInAuditSessionOfCurrentUser(ctx, "security", []string{"add-trusted-cert",
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
			_, err := RunInAuditSessionOfCurrentUser(ctx, "security", []string{"delete-certificate",
				"-Z", hash,
				"/Library/Keychains/System.keychain"})
			if err != nil {
				errs = append(errs, err)
			}
		}
	}

	if _, err := RunInAuditSessionOfCurrentUser(ctx, "security", []string{"delete-generic-password",
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

func GetCurrentUser(ctx context.Context) (string, int, string, int, error) {
	output, err := exec.CommandContext(ctx, "stat", "-f", "%Su %u %Sg %g", "/dev/console").Output()
	if err != nil {
		return "", 0, "", 0, fmt.Errorf("failed to get console user: %v", err)
	}
	parts := strings.Fields(string(output))
	if len(parts) != 4 {
		return "", 0, "", 0, fmt.Errorf("unexpected stat output: %s", output)
	}
	username, uid, group, gid := parts[0], parts[1], parts[2], parts[3]
	if username == "" || username == "root" {
		return "", 0, "", 0, fmt.Errorf("no interactive user logged in")
	}
	uidInt, err := strconv.Atoi(uid)
	if err != nil {
		return "", 0, "", 0, fmt.Errorf("failed to convert uid to int: %w", err)
	}
	gidInt, err := strconv.Atoi(gid)
	if err != nil {
		return "", 0, "", 0, fmt.Errorf("failed to convert gid to int: %w", err)
	}
	return username, uidInt, group, gidInt, nil
}

func RunAsCurrentUser(ctx context.Context, binaryPath string, args []string) (string, error) {
	if !RunningAsRoot() {
		return utils.RunCommand(ctx, binaryPath, args...)
	}

	username, _, _, _, err := GetCurrentUser(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get console user: %v", err)
	}

	suArgs := append([]string{"-u", username, binaryPath}, args...)
	return utils.RunCommandWithEnv(ctx, []string{}, "sudo", suArgs...)
}

func RunInAuditSessionOfCurrentUser(ctx context.Context, binaryPath string, args []string) (string, error) {
	if !RunningAsRoot() {
		return utils.RunCommand(ctx, binaryPath, args...)
	}

	_, uid, _, _, err := GetCurrentUser(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get console user: %v", err)
	}

	uidStr := fmt.Sprintf("%d", uid)
	launchctlArgs := append([]string{"asuser", uidStr, binaryPath}, args...)
	return utils.RunCommandWithEnv(ctx, []string{}, "launchctl", launchctlArgs...)
}

// StartUIProcessInAuditSessionOfCurrentUser starts the process as the current user and returns its PID.
// The process is not waited on; the caller may kill it later using the PID.
func StartUIProcessInAuditSessionOfCurrentUser(ctx context.Context, binaryPath string, args []string) (int, error) {
	if !RunningAsRoot() {
		cmd := exec.CommandContext(ctx, binaryPath, args...)
		if err := cmd.Start(); err != nil {
			return 0, err
		}
		return cmd.Process.Pid, nil
	}
	_, uid, _, _, err := GetCurrentUser(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get console user: %v", err)
	}
	uidStr := fmt.Sprintf("%d", uid)
	launchctlArgs := append([]string{"asuser", uidStr, binaryPath}, args...)
	cmd := exec.CommandContext(ctx, "launchctl", launchctlArgs...)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

func RunningAsRoot() bool {
	return os.Getuid() == 0
}

func downloadSafeChainShellScript(ctx context.Context, repoURL, version string, scriptName string) (string, error) {
	scriptURL := fmt.Sprintf("%s/releases/download/%s/%s", repoURL, version, scriptName)
	scriptPath := filepath.Join(os.TempDir(), scriptName)
	verification := utils.DownloadVerification{
		SafeChainReleaseTag: version,
		SafeChainAssetName:  scriptName,
	}

	log.Printf("Downloading script %s from %s...", scriptName, scriptURL)
	if err := utils.DownloadAndVerifyBinary(ctx, scriptURL, scriptPath, verification); err != nil {
		return "", fmt.Errorf("failed to download script %s: %w", scriptName, err)
	}
	return scriptPath, nil
}

func InstallSafeChain(ctx context.Context, repoURL, version string) error {
	scriptPath, err := downloadSafeChainShellScript(ctx, repoURL, version, SafeChainInstallScriptName)
	if err != nil {
		return err
	}
	_, uid, _, gid, err := GetCurrentUser(ctx)
	if err != nil {
		return fmt.Errorf("failed to get console user: %w", err)
	}
	if err := os.Chown(scriptPath, uid, gid); err != nil {
		return fmt.Errorf("failed to set install script ownership: %w", err)
	}
	defer os.Remove(scriptPath)
	if _, err := RunAsCurrentUser(ctx, "sh", []string{scriptPath}); err != nil {
		return fmt.Errorf("failed to run install script: %w", err)
	}
	return nil
}

func GetOSVersion() string {
	version, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(version)
}

func GetRawDeviceID() (string, error) {
	output, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run ioreg: %w", err)
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		uuid := strings.TrimSpace(parts[1])
		uuid = strings.Trim(uuid, "\"")
		if uuid != "" {
			return uuid, nil
		}
	}

	return "", fmt.Errorf("IOPlatformUUID not found in ioreg output")
}

func UninstallSafeChain(ctx context.Context, repoURL, version string) error {
	scriptPath, err := downloadSafeChainShellScript(ctx, repoURL, version, SafeChainUninstallScriptName)
	if err != nil {
		return err
	}
	defer os.Remove(scriptPath)

	if _, err := RunAsCurrentUser(ctx, "sh", []string{scriptPath}); err != nil {
		return fmt.Errorf("failed to run uninstall script: %w", err)
	}
	return nil
}
