package platform

import (
	"context"
	"io"
	"os"
)

var homeDir, _ = os.UserHomeDir()

type Config struct {
	LogDir               string
	BinaryDir            string
	RunDir               string
	SafeChainBinaryPath  string
	SafeChainProxyRunDir string
}

func GetConfig() *Config {
	return getConfig()
}

func PrepareShellEnvironment(ctx context.Context) error {
	return prepareShellEnvironment(ctx)
}

func SetupLogging() (io.Writer, error) {
	return setupLogging()
}

func SetSystemProxy(ctx context.Context, proxyURL string) error {
	return setSystemProxy(ctx, proxyURL)
}

func UnsetSystemProxy(ctx context.Context) error {
	return unsetSystemProxy(ctx)
}
