//go:build windows

package platform

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
)

const (
	SafeChainProxyBinaryName = "SafeChainProxy.exe"
	SafeChainProxyLogName    = "SafeChainProxy.log"
	registryInternetSettings = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	proxyOverride            = "<local>,localhost,127.0.0.1"
)

// Configuration folders are configured and cleaned up in the Windows MSI install (packaging/windows/SafeChainAgent.wxs)
func initConfig() error {
	programDataDir := filepath.Join(os.Getenv("ProgramData"), "AikidoSecurity", "SafeChainAgent")
	config.BinaryDir = `C:\Program Files\AikidoSecurity\SafeChainAgent\bin`
	config.LogDir = filepath.Join(programDataDir, "logs")
	config.RunDir = filepath.Join(programDataDir, "run")
	config.SafeChainBinaryPath = filepath.Join(programDataDir, "bin", "safe-chain.exe")
	return nil
}

// PrepareShellEnvironment sets the PowerShell execution policy to RemoteSigned for the current user.
// This is necessary to allow the safe-chain binary to execute PowerShell scripts during setup,
// such as modifying the PowerShell profile for shell integration.
func PrepareShellEnvironment(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "powershell", "-Command",
		"Set-ExecutionPolicy", "-ExecutionPolicy", "RemoteSigned", "-Scope", "CurrentUser", "-Force")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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

	logPath := filepath.Join(config.LogDir, "SafeChainAgent.log")
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

func SetSystemProxy(ctx context.Context, proxyURL string) error {
	cmd := exec.CommandContext(ctx, "netsh", "winhttp", "set", "proxy", proxyURL)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	regCmds := [][]string{
		{"reg", "add", registryInternetSettings, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"},
		{"reg", "add", registryInternetSettings, "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyURL, "/f"},
		{"reg", "add", registryInternetSettings, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", proxyOverride, "/f"},
	}
	for _, args := range regCmds {
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		log.Printf("Running command: %q", strings.Join(args, " "))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func IsSystemProxySet(ctx context.Context, proxyURL string) bool {
	cmd := exec.CommandContext(ctx, "netsh", "winhttp", "show", "proxy")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	if strings.Contains(string(output), "Direct access") {
		return false
	}

	regCmd := exec.CommandContext(ctx, "reg", "query", registryInternetSettings, "/v", "ProxyEnable")
	regOutput, err := regCmd.Output()
	if err != nil || !strings.Contains(string(regOutput), "0x1") {
		return false
	}

	regCmd = exec.CommandContext(ctx, "reg", "query", registryInternetSettings, "/v", "ProxyServer")
	regOutput, err = regCmd.Output()
	if err != nil || !strings.Contains(string(regOutput), proxyURL) {
		return false
	}

	return true
}

func UnsetSystemProxy(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "netsh", "winhttp", "reset", "proxy")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	regCmds := [][]string{
		{"reg", "add", registryInternetSettings, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"},
		{"reg", "delete", registryInternetSettings, "/v", "ProxyServer", "/f"},
		{"reg", "delete", registryInternetSettings, "/v", "ProxyOverride", "/f"},
	}
	for _, args := range regCmds {
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		log.Printf("Running command: %q", strings.Join(args, " "))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to run %q: %v", strings.Join(args, " "), err)
		}
	}
	return nil
}

func InstallProxyCA(ctx context.Context, caCertPath string) error {
	cmd := exec.CommandContext(ctx, "certutil", "-addstore", "-f", "Root", caCertPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func IsProxyCAInstalled(ctx context.Context) bool {
	return true
}

func UninstallProxyCA(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "certutil", "-delstore", "Root", "aikido.dev")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
