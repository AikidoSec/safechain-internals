//go:build linux

package platform

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/utils"
)

const (
	SafeChainUltimateLogName     = "safechain-ultimate.log"
	SafeChainUltimateErrLogName  = "safechain-ultimate.error.log"
	SafeChainUIBinaryName        = "safechain-ultimate-ui"
	SafeChainProxyBinaryName     = "safechain-proxy"
	SafeChainProxyLogName        = "safechain-proxy.log"
	SafeChainProxyErrLogName     = "safechain-proxy.err"
	SafeChainInstallScriptName   = "install-safe-chain.sh"
	SafeChainUninstallScriptName = "uninstall-safe-chain.sh"

	systemCertDir = "/usr/local/share/ca-certificates"
	certFileName  = "aikidosafechain.crt"
)

func initConfig() error {
	if RunningAsRoot() {
		username, err := getLoggedInUser(context.Background())
		if err != nil {
			return fmt.Errorf("failed to get logged in user: %v", err)
		}
		config.HomeDir = filepath.Join("/home", username)
	} else {
		var err error
		config.HomeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %v", err)
		}
	}
	safeChainHomeDir := filepath.Join(config.HomeDir, ".safe-chain")
	config.BinaryDir = "/opt/aikidosecurity/safechainultimate/bin"
	config.RunDir = "/opt/aikidosecurity/safechainultimate/run"
	config.LogDir = "/var/log/aikidosecurity/safechainultimate"
	config.SafeChainBinaryPath = filepath.Join(safeChainHomeDir, "bin", "safe-chain")
	return nil
}

func PrepareShellEnvironment(_ context.Context) error {
	return nil
}

func SetupLogging() (io.Writer, error) {
	return os.Stdout, nil
}

func getGsettingsProxy(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "gsettings", "get", "org.gnome.system.proxy", "mode").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.Trim(string(output), "'")), nil
}

func getGsettingsAutoConfigURL(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "gsettings", "get", "org.gnome.system.proxy", "autoconfig-url").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.Trim(string(output), "'")), nil
}

func hasGsettings() bool {
	_, err := exec.LookPath("gsettings")
	return err == nil
}

func SetSystemPAC(ctx context.Context, pacURL string) error {
	if !hasGsettings() {
		log.Println("gsettings not available, setting proxy environment variables only")
		return setEnvironmentProxy(pacURL)
	}

	log.Printf("Setting system PAC to %q via gsettings\n", pacURL)
	if err := exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", pacURL).Run(); err != nil {
		return fmt.Errorf("failed to set autoconfig-url: %v", err)
	}
	if err := exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "mode", "auto").Run(); err != nil {
		return fmt.Errorf("failed to set proxy mode to auto: %v", err)
	}
	return nil
}

func IsSystemPACSet(ctx context.Context, pacURL string) error {
	if !hasGsettings() {
		return isEnvironmentProxySet(pacURL)
	}

	mode, err := getGsettingsProxy(ctx)
	if err != nil {
		return fmt.Errorf("failed to get proxy mode: %v", err)
	}
	if mode != "auto" {
		return fmt.Errorf("proxy mode is %q, expected 'auto'", mode)
	}

	configURL, err := getGsettingsAutoConfigURL(ctx)
	if err != nil {
		return fmt.Errorf("failed to get autoconfig-url: %v", err)
	}
	if configURL != pacURL {
		return fmt.Errorf("autoconfig-url is %q, expected %q", configURL, pacURL)
	}
	return nil
}

func IsAnySystemProxySet(ctx context.Context) (bool, error) {
	if !hasGsettings() {
		return isAnyEnvironmentProxySet(), nil
	}

	mode, err := getGsettingsProxy(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get proxy mode: %v", err)
	}
	return mode != "none" && mode != "", nil
}

func UnsetSystemPAC(ctx context.Context, pacURL string) error {
	if !hasGsettings() {
		return unsetEnvironmentProxy()
	}

	log.Println("Unsetting system PAC via gsettings")
	errs := []error{}
	if err := exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", "").Run(); err != nil {
		errs = append(errs, err)
	}
	if err := exec.CommandContext(ctx, "gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to unset system PAC: %v", errs)
	}
	return nil
}

func setEnvironmentProxy(pacURL string) error {
	proxyEnvFile := "/etc/profile.d/safechain-proxy.sh"
	content := fmt.Sprintf("# SafeChain Ultimate proxy configuration\nexport auto_proxy=\"%s\"\n", pacURL)
	if err := os.WriteFile(proxyEnvFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write proxy environment file: %v", err)
	}
	return nil
}

func isEnvironmentProxySet(pacURL string) error {
	proxyEnvFile := "/etc/profile.d/safechain-proxy.sh"
	content, err := os.ReadFile(proxyEnvFile)
	if err != nil {
		return fmt.Errorf("proxy environment file not found: %v", err)
	}
	if !strings.Contains(string(content), pacURL) {
		return fmt.Errorf("proxy environment file does not contain expected PAC URL")
	}
	return nil
}

func isAnyEnvironmentProxySet() bool {
	proxyEnvFile := "/etc/profile.d/safechain-proxy.sh"
	_, err := os.Stat(proxyEnvFile)
	return err == nil
}

func unsetEnvironmentProxy() error {
	proxyEnvFile := "/etc/profile.d/safechain-proxy.sh"
	if err := os.Remove(proxyEnvFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove proxy environment file: %v", err)
	}
	return nil
}

func InstallProxyCA(_ context.Context, certPath string) error {
	destPath := filepath.Join(systemCertDir, certFileName)
	if err := os.MkdirAll(systemCertDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %v", err)
	}
	input, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %v", err)
	}
	if err := os.WriteFile(destPath, input, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}
	if _, err := exec.Command("update-ca-certificates").Output(); err != nil {
		return fmt.Errorf("failed to update ca certificates: %v", err)
	}
	return nil
}

func IsProxyCAInstalled(_ context.Context) error {
	destPath := filepath.Join(systemCertDir, certFileName)
	if _, err := os.Stat(destPath); os.IsNotExist(err) {
		return fmt.Errorf("proxy CA certificate not found at %s", destPath)
	}
	return nil
}

func UninstallProxyCA(_ context.Context) error {
	errs := []error{}

	destPath := filepath.Join(systemCertDir, certFileName)
	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("failed to remove certificate: %v", err))
	}

	if _, err := exec.Command("update-ca-certificates", "--fresh").Output(); err != nil {
		errs = append(errs, fmt.Errorf("failed to update ca certificates: %v", err))
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

func getLoggedInUser(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "loginctl", "list-users", "--no-legend").Output()
	if err != nil {
		envUser := os.Getenv("SUDO_USER")
		if envUser != "" {
			return envUser, nil
		}
		return "", fmt.Errorf("failed to get logged in user: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] != "root" {
			return fields[1], nil
		}
	}

	envUser := os.Getenv("SUDO_USER")
	if envUser != "" {
		return envUser, nil
	}
	return "", fmt.Errorf("no interactive user found")
}

func RunAsCurrentUser(ctx context.Context, binaryPath string, args []string) (string, error) {
	if !RunningAsRoot() {
		return utils.RunCommand(ctx, binaryPath, args...)
	}

	username, err := getLoggedInUser(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get logged in user: %v", err)
	}

	suArgs := append([]string{"-u", username, binaryPath}, args...)
	return utils.RunCommandWithEnv(ctx, []string{}, "sudo", suArgs...)
}

func RunInAuditSessionOfCurrentUser(ctx context.Context, binaryPath string, args []string) (string, error) {
	return RunAsCurrentUser(ctx, binaryPath, args)
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
	defer os.Remove(scriptPath)
	if _, err := RunAsCurrentUser(ctx, "sh", []string{scriptPath}); err != nil {
		return fmt.Errorf("failed to run install script: %w", err)
	}
	return nil
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
