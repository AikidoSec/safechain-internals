//go:build !darwin && !windows

package platform

import "os"

func InstallMavenOptsOverride(_ string) error { return nil }

func UninstallMavenOptsOverride(_ string) error { return nil }

func GetMavenHomeDir() (string, error) {
	if config.HomeDir != "" {
		return config.HomeDir, nil
	}
	return os.UserHomeDir()
}
