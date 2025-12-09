//go:build darwin

package platform

func getConfig() *Config {
	return &Config{
		BinDir: "/opt/homebrew/bin",
	}
}
