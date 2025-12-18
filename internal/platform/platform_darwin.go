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
		SafeChainBinaryPath: filepath.Join(homeDir, ".safe-chain", "bin", "safe-chain"),
	}
}

func prepareShellEnvironment(ctx context.Context) error {
	return nil
}

func setupLogging() (io.Writer, error) {
	return os.Stdout, nil
}
