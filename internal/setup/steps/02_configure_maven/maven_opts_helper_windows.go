//go:build windows

package configure_maven

import "context"

// Windows implementation intentionally stubbed for now.
// TODO in follow up PR
func installMavenOptsOverride(_ context.Context, _ string) error { return nil }

func uninstallMavenOptsOverride(_ context.Context, _ string) error { return nil }
