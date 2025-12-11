package platform

type Config struct {
	SafeChainBinary string
}

func Get() *Config {
	return getConfig()
}
