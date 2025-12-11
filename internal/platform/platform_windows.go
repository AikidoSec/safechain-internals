//go:build windows

package platform

func getConfig() *Config {
	return &Config{
		SafeChainBinary: "C:\\Program Files\\AikidoSecurity\\sc-agent\\bin\\safe-chain.exe",
	}
}
