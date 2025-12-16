//go:build linux

package platform

import (
	"context"
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
