package platform

import (
	"context"
	"io"
	"os"
)

var homeDir, _ = os.UserHomeDir()

type Config struct {
	SafeChainBinaryPath string
	SafeChainProxyDir   string
	LogDir              string
}

func Get() *Config {
	return getConfig()
}

func PrepareShellEnvironment(ctx context.Context) error {
	return prepareShellEnvironment(ctx)
}

func SetupLogging() (io.Writer, error) {
	return setupLogging()
}
