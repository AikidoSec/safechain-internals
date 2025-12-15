package platform

import "os"

var homeDir, _ = os.UserHomeDir()

type Config struct {
	SafeChainBinary string
}

func Get() *Config {
	return getConfig()
}
