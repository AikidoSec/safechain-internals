//go:build !darwin && !windows

package configure_maven

// Non-macOS and non-Windows implementation intentionally stubbed for now.
// TODO in follow up PR
func installMavenOptsOverride(_ string) error { return nil }

func uninstallMavenOptsOverride(_ string) error { return nil }
