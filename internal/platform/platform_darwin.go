//go:build darwin

package platform

func getConfig() *Config {
	return &Config{
		SafeChainBinary: "/opt/homebrew/bin/sc-agent",
	}
}
