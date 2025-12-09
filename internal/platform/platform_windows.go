//go:build windows

package platform

func getConfig() *Config {
	return &Config{
		BinDir: "",
	}
}
