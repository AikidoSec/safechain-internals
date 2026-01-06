package platform

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Config struct {
	BinaryDir            string
	RunDir               string
	LogDir               string
	SafeChainBinaryPath  string
	SafeChainProxyRunDir string
}

var config Config

func Init() error {
	if err := initConfig(); err != nil {
		return err
	}

	if err := os.MkdirAll(config.RunDir, 0755); err != nil {
		return fmt.Errorf("failed to create run directory: %v", err)
	}
	if err := os.MkdirAll(config.LogDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}
	return nil
}

func GetConfig() *Config {
	return &config
}

func GetProxyRunDir() string {
	return config.RunDir
}

func GetProxySetupFinishedMarker() string {
	return filepath.Join(GetProxyRunDir(), ".setup_finished")
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

func InstallProxyCA(ctx context.Context, caCertPath string) error {
	return installProxyCA(ctx, caCertPath)
}

func IsProxyCAInstalled(ctx context.Context) error {
	return isProxyCAInstalled(ctx)
}

func UninstallProxyCA(ctx context.Context) error {
	return uninstallProxyCA(ctx)
}
