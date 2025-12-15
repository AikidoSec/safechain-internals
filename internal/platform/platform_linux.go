//go:build linux

package platform

import "path/filepath"

func getConfig() *Config {
	return &Config{
		SafeChainBinary: filepath.Join(homeDir, ".safe-chain", "bin", "safe-chain"),
	}
}
