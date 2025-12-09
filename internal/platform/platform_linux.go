//go:build linux

package platform

func getConfig() *Config {
	return &Config{
		BinDir: "/usr/local/bin",
	}
}
