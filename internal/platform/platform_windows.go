//go:build windows

package platform

import "path/filepath"

func getConfig() *Config {
	return &Config{
		SafeChainBinaryPath: filepath.Join(homeDir, ".safe-chain", "bin", "safe-chain.exe"),
	}
}
