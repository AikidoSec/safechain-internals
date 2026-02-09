package platform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	HomeDir             string
	BinaryDir           string
	RunDir              string
	LogDir              string
	SafeChainBinaryPath string
}

var config Config

func Init() error {
	if err := initConfig(); err != nil {
		return err
	}

	if err := os.MkdirAll(config.RunDir, 0755); err != nil {
		return fmt.Errorf("failed to create run directory %s: %v", config.RunDir, err)
	}
	if err := os.MkdirAll(config.LogDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory %s: %v", config.LogDir, err)
	}
	return nil
}

func GetConfig() *Config {
	return &config
}

func GetRunDir() string {
	return config.RunDir
}

func GetLogDir() string {
	return config.LogDir
}

func GetUltimateLogPath() string {
	return filepath.Join(config.LogDir, SafeChainUltimateLogName)
}

func GetUltimateErrLogPath() string {
	return filepath.Join(config.LogDir, SafeChainUltimateErrLogName)
}

func GetProxyLogPath() string {
	return filepath.Join(config.LogDir, SafeChainProxyLogName)
}

func GetProxyErrLogPath() string {
	return filepath.Join(config.LogDir, SafeChainProxyErrLogName)
}

type ServiceRunner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}
