//go:build darwin

package platform

import (
	"context"
	"io"
	"os"
	"path/filepath"
)

func getConfig() *Config {
	return &Config{
		BinaryDir:           "/opt/homebrew/bin/",
		RunDir:              "/opt/homebrew/var/run/",
		LogDir:              "/opt/homebrew/var/log/",
		SafeChainBinaryPath: filepath.Join(homeDir, ".safe-chain", "bin", "safe-chain"),
	}
}

func prepareShellEnvironment(ctx context.Context) error {
	return nil
}

func setupLogging() (io.Writer, error) {
	return os.Stdout, nil
}
