//go:build windows

package platform

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	SafeChainUltimateLogName       = "SafeChainUltimate.log"
	SafeChainUltimateErrLogName    = "SafeChainUltimate.err"
	SafeChainUIBinaryName          = "SafeChainUltimateUI.exe"
	SafeChainProxyBinaryName       = "SafeChainProxy.exe"
	SafeChainProxyLogName          = "SafeChainProxy.log"
	SafeChainProxyErrLogName       = "SafeChainProxy.err"
	SafeChainInstallScriptName     = "install-safe-chain.ps1"
	SafeChainUninstallScriptName   = "uninstall-safe-chain.ps1"
	registryInternetSettingsSuffix = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
)

func initConfig() error {
	programDataDir := filepath.Join(os.Getenv("ProgramData"), "AikidoSecurity", "SafeChainUltimate")
	config.BinaryDir = `C:\Program Files\AikidoSecurity\SafeChainUltimate\bin`
	config.LogDir = filepath.Join(programDataDir, "logs")
	config.RunDir = filepath.Join(programDataDir, "run")

	var err error
	config.HomeDir, err = GetActiveUserHomeDir()
	if err != nil {
		config.HomeDir, err = os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %v", err)
		}
	}
	log.Println("User home directory used for SafeChain:", config.HomeDir)
	safeChainDir := filepath.Join(config.HomeDir, ".safe-chain")
	config.SafeChainBinaryPath = filepath.Join(safeChainDir, "bin", "safe-chain.exe")
	return nil
}

func GetActiveUserHomeDir() (string, error) {
	if !IsWindowsService() {
		return os.UserHomeDir()
	}

	sessionID, err := getActiveUserSessionID()
	if err != nil {
		return "", err
	}

	var userToken windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &userToken); err != nil {
		return "", fmt.Errorf("WTSQueryUserToken failed: %v", err)
	}
	defer userToken.Close()

	return userToken.GetUserProfileDirectory()
}

// PrepareShellEnvironment sets the PowerShell execution policy to RemoteSigned for the current user.
// This is necessary to allow the safe-chain binary to execute PowerShell scripts during setup,
// such as modifying the PowerShell profile for shell integration.
// As safe-chain will run as the current user, we need to set the PowerShell execution policy for the current user.
func PrepareShellEnvironment(ctx context.Context) error {
	_, err := RunAsCurrentUser(ctx, "powershell", []string{"-Command",
		"Set-ExecutionPolicy", "-ExecutionPolicy", "RemoteSigned", "-Scope", "CurrentUser", "-Force"})
	return err
}

type syncWriter struct {
	f *os.File
}

func (w *syncWriter) Write(p []byte) (n int, err error) {
	n, err = w.f.Write(p)
	if err != nil {
		return n, err
	}
	return n, w.f.Sync()
}

func SetupLogging() (io.Writer, error) {
	if err := os.MkdirAll(config.LogDir, 0755); err != nil {
		return os.Stdout, err
	}

	logPath := filepath.Join(config.LogDir, SafeChainUltimateLogName)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return os.Stdout, err
	}

	fileWriter := &syncWriter{f: f}
	if IsWindowsService() {
		return fileWriter, nil
	}

	return io.MultiWriter(os.Stdout, fileWriter), nil
}

func SetSystemPAC(ctx context.Context, pacURL string) error {
	sids, err := getLoggedInUserSIDs(ctx)
	if err != nil {
		return err
	}

	for _, sid := range sids {
		regPath := `HKU\` + sid + `\` + registryInternetSettingsSuffix
		regCmds := []RegistryValue{
			{Type: "REG_SZ", Value: "AutoConfigURL", Data: pacURL}, // URL to be used as PAC by the OS
		}
		for _, value := range regCmds {
			if err := setRegistryValue(ctx, regPath, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func isSystemProxySetForSid(ctx context.Context, sid string) bool {
	regPath := `HKU\` + sid + `\` + registryInternetSettingsSuffix
	return registryValueContains(ctx, regPath, "ProxyEnable", "0x1")
}

func isSystemPACSetForSid(ctx context.Context, sid string, pacURL string) bool {
	regPath := `HKU\` + sid + `\` + registryInternetSettingsSuffix
	return registryValueContains(ctx, regPath, "AutoConfigURL", pacURL)
}

func IsSystemPACSet(ctx context.Context, pacURL string) error {
	sids, err := getLoggedInUserSIDs(ctx)
	if err != nil || len(sids) == 0 {
		return fmt.Errorf("failed to get logged in user sids: %v", err)
	}

	for _, sid := range sids {
		if !isSystemPACSetForSid(ctx, sid, pacURL) {
			return fmt.Errorf("system PAC is not set for user %s", sid)
		}
	}
	return nil
}

func IsAnySystemProxySet(ctx context.Context) (bool, error) {
	sids, err := getLoggedInUserSIDs(ctx)
	if err != nil {
		return false, err
	}
	for _, sid := range sids {
		if isSystemProxySetForSid(ctx, sid) || isSystemPACSetForSid(ctx, sid, "") {
			return true, nil
		}
	}
	return false, nil
}

func UnsetSystemPAC(ctx context.Context, pacURL string) error {
	errs := []error{}
	sids, err := getLoggedInUserSIDs(ctx)
	if err != nil {
		return err
	}

	for _, sid := range sids {
		regPath := `HKU\` + sid + `\` + registryInternetSettingsSuffix
		regValuesToDisable := map[string]RegistryValue{
			"AutoConfigURL": {Type: "REG_SZ", Value: "AutoConfigURL", Data: ""},
		}
		for _, regValue := range regValuesToDisable {
			if err := setRegistryValue(ctx, regPath, regValue); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to unset system proxy: %v", errs)
	}
	return nil
}

func InstallProxyCA(ctx context.Context, caCertPath string) error {
	_, err := utils.RunCommand(ctx, "certutil", "-addstore", "-f", "Root", caCertPath)
	return err
}

func IsProxyCAInstalled(ctx context.Context) error {
	// certutil returns non-zero exit code if the certificate is not installed
	_, err := utils.RunCommand(ctx, "certutil", "-store", "Root", "aikidosafechain.com")
	return err
}

func UninstallProxyCA(ctx context.Context) error {
	commandsToExecute := []utils.Command{
		{Command: "certutil", Args: []string{"-delstore", "Root", "aikidosafechain.com"}},
		{Command: "cmdkey", Args: []string{"/delete:safechain-proxy.tls-root-ca-key"}},
	}
	_, err := utils.RunCommands(ctx, commandsToExecute)
	if err != nil {
		return err
	}
	return nil
}

type ServiceRunner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

type windowsService struct {
	runner ServiceRunner
}

func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		if err := s.runner.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case err := <-errChan:
			log.Printf("Service runner error: %v", err)
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				log.Printf("Received service control: %v", c.Cmd)
				break loop
			default:
				log.Printf("Unexpected service control request: %v", c.Cmd)
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := s.runner.Stop(shutdownCtx); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	return false, 0
}

func IsWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("Failed to determine if running as Windows service: %v", err)
		return false
	}
	return isService
}

func RunAsWindowsService(runner ServiceRunner, serviceName string) error {
	return svc.Run(serviceName, &windowsService{runner: runner})
}

func RunAsCurrentUser(ctx context.Context, binaryPath string, args []string) (string, error) {
	if !IsWindowsService() {
		return utils.RunCommand(ctx, binaryPath, args...)
	}

	return runAsLoggedInUser(binaryPath, args)
}

func RunInAuditSessionOfCurrentUser(ctx context.Context, binaryPath string, args []string) (string, error) {
	return RunAsCurrentUser(ctx, binaryPath, args)
}

func downloadAndRunSafeChainPowerShellScript(ctx context.Context, repoURL, version string, scriptName string, tempFilePattern string) error {
	scriptURL := fmt.Sprintf("%s/releases/download/%s/%s", repoURL, version, scriptName)
	verification := utils.DownloadVerification{
		SafeChainReleaseTag: version,
		SafeChainAssetName:  scriptName,
	}
	if err := os.MkdirAll(config.RunDir, 0755); err != nil {
		return fmt.Errorf("failed to create run dir: %w", err)
	}

	tmpFile, err := os.CreateTemp(config.RunDir, tempFilePattern)
	if err != nil {
		return fmt.Errorf("failed to create temp script file: %w", err)
	}
	scriptPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(scriptPath)

	log.Printf("Downloading PowerShell script %s from %s...", scriptName, scriptURL)
	if err := utils.DownloadAndVerifyBinary(ctx, scriptURL, scriptPath, verification); err != nil {
		return fmt.Errorf("failed to download script %s: %w", scriptName, err)
	}

	log.Printf("Running PowerShell script %s...", scriptPath)
	if _, err := RunAsCurrentUser(ctx, "powershell", []string{"-ExecutionPolicy", "RemoteSigned", "-File", scriptPath}); err != nil {
		return fmt.Errorf("failed to run script %s: %w", scriptName, err)
	}
	return nil
}

func InstallSafeChain(ctx context.Context, repoURL, version string) error {
	return downloadAndRunSafeChainPowerShellScript(
		ctx,
		repoURL,
		version,
		SafeChainInstallScriptName,
		"install-safe-chain-*.ps1",
	)
}

func UninstallSafeChain(ctx context.Context, repoURL, version string) error {
	return downloadAndRunSafeChainPowerShellScript(
		ctx,
		repoURL,
		version,
		SafeChainUninstallScriptName,
		"uninstall-safe-chain-*.ps1",
	)
}
