package platform

import (
	"fmt"
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

func GetProxyRunDir() string {
	return config.RunDir
}

func GetProxySetupFinishedMarker() string {
	return filepath.Join(GetProxyRunDir(), ".setup_finished")
}
