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

func getConfig() *Config {
	return &Config{
		LogDir:               filepath.Join(os.Getenv("ProgramData"), "AikidoSecurity", "SafeChainAgent", "logs"),
		RunDir:               filepath.Join(os.Getenv("ProgramData"), "AikidoSecurity", "SafeChainAgent", "run"),
		SafeChainBinaryPath:  filepath.Join(homeDir, ".safe-chain", "bin", "safe-chain.exe"),
		SafeChainProxyRunDir: filepath.Join(homeDir, ".aikido", "safechain-proxy"),
	}
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
