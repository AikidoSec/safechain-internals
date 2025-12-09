package platform

type Config struct {
	BinDir string
}

func Get() *Config {
	return getConfig()
}
