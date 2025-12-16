package platform

import "os"

var homeDir, _ = os.UserHomeDir()

type Config struct {
	SafeChainBinaryPath string
}

func Get() *Config {
	return getConfig()
}
