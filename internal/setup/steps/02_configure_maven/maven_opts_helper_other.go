//go:build !darwin && !windows

package configure_maven

import "context"

// Non-macOS and non-Windows implementation intentionally stubbed for now.
// TODO in follow up PR
func installMavenOptsOverride(_ context.Context, _ string) error { return nil }

func uninstallMavenOptsOverride(_ context.Context, _ string) error { return nil }
