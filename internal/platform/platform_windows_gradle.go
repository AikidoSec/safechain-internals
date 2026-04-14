//go:build windows

package platform

func InstallGradleSystemPropsOverride(_ string) error { return nil }

func UninstallGradleSystemPropsOverride(_ string) error { return nil }
