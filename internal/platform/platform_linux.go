//go:build linux

package platform

func getConfig() *Config {
	return &Config{
		SafeChainBinary: "/usr/local/bin/safe-chain",
	}
}
