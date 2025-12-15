//go:build windows

package platform

func getConfig() *Config {
	return &Config{
		SafeChainBinary: "C:\\Program Files\\AikidoSecurity\\aikido-agent\\bin\\safe-chain.exe",
	}
}
