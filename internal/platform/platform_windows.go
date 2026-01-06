//go:build windows

package platform

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

// prepareShellEnvironment sets the PowerShell execution policy to RemoteSigned for the current user.
// This is necessary to allow the safe-chain binary to execute PowerShell scripts during setup,
// such as modifying the PowerShell profile for shell integration.
func prepareShellEnvironment(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "powershell", "-Command",
		"Set-ExecutionPolicy", "-ExecutionPolicy", "RemoteSigned", "-Scope", "CurrentUser", "-Force")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func setupLogging() (io.Writer, error) {
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

func setSystemProxy(ctx context.Context, proxyURL string) error {
	return nil
}

func unsetSystemProxy(ctx context.Context) error {
	return nil
}

func installProxyCA(ctx context.Context, caCertPath string) error {
	return nil
}

func isProxyCAInstalled(ctx context.Context) bool {
	return false
}

func uninstallProxyCA(ctx context.Context) error {
	return nil
}
