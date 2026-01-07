//go:build windows

package platform

import (
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
)

var logDir = filepath.Join(os.Getenv("ProgramData"), "AikidoSecurity", "SafeChainAgent", "logs")

func initConfig() error {
	safeChainHomeDir := filepath.Join(os.Getenv("ProgramData"), "AikidoSecurity", "SafeChain")
	config.LogDir = filepath.Join(safeChainHomeDir, "logs")
	config.RunDir = filepath.Join(safeChainHomeDir, "run")
	config.SafeChainBinaryPath = filepath.Join(safeChainHomeDir, "bin", "safe-chain.exe")
	config.SafeChainProxyRunDir = filepath.Join(safeChainHomeDir, "run", "safechain-proxy")
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

func SetupLogging() (io.Writer, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return os.Stdout, err
	}

	logPath := filepath.Join(logDir, "safechain-agent.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return os.Stdout, err
	}

	return io.MultiWriter(os.Stdout, f), nil
}

func SetSystemProxy(ctx context.Context, proxyURL string) error {
	return nil
}

func UnsetSystemProxy(ctx context.Context) error {
	return nil
}

func InstallProxyCA(ctx context.Context, caCertPath string) error {
	return nil
}

func IsProxyCAInstalled(ctx context.Context) bool {
	return false
}

func UninstallProxyCA(ctx context.Context) error {
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
