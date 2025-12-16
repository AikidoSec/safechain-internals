package platform

import (
	"context"
	"os"
)

var homeDir, _ = os.UserHomeDir()

type Config struct {
	SafeChainBinaryPath string
}

func Get() *Config {
	return getConfig()
}

func PrepareShellEnvironment(ctx context.Context) error {
	return prepareShellEnvironment(ctx)
}
