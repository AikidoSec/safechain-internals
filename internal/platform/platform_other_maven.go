//go:build !darwin && !windows

package platform

func InstallMavenOptsOverride(_ string) error { return nil }

func UninstallMavenOptsOverride(_ string) error { return nil }
