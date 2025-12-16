//go:build windows

package platform

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

func getConfig() *Config {
	return &Config{
		SafeChainBinaryPath: filepath.Join(homeDir, ".safe-chain", "bin", "safe-chain.exe"),
	}
}

func prepareShellEnvironment(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "powershell", "-Command",
		"Set-ExecutionPolicy", "-ExecutionPolicy", "RemoteSigned", "-Scope", "CurrentUser", "-Force")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
