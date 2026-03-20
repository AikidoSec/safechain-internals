package certconfig

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

var firefoxManagedBlockFormat = managedBlockFormat{
	startMarker: "// aikido-cert-config-start",
	endMarker:   "// aikido-cert-config-end",
}

type firefoxConfigurator struct{}

func newFirefoxConfigurator() Configurator {
	return &firefoxConfigurator{}
}

func (c *firefoxConfigurator) Name() string {
	return "firefox"
}

func (c *firefoxConfigurator) Install(_ context.Context) error {
	for _, profile := range firefoxProfiles() {
		path := filepath.Join(profile, "user.js")
		body := `user_pref("security.enterprise_roots.enabled", true);`
		if err := writeManagedBlock(path, body, 0o644, firefoxManagedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

func (c *firefoxConfigurator) Uninstall(_ context.Context) error {
	for _, profile := range firefoxProfiles() {
		path := filepath.Join(profile, "user.js")
		if err := removeManagedBlock(path, 0o644, firefoxManagedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

func firefoxProfiles() []string {
	profilesRoot := firefoxProfilesRoot()
	if profilesRoot == "" {
		return nil
	}

	if _, err := os.Stat(profilesRoot); err != nil {
		return nil
	}

	entries, err := os.ReadDir(profilesRoot)
	if err != nil {
		return nil
	}

	profiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Firefox profile dirs always follow the "{salt}.{name}" naming convention,
		// so any directory containing a dot is a profile directory.
		if strings.Contains(entry.Name(), ".") {
			profilePath := filepath.Join(profilesRoot, entry.Name())
			if isFirefoxProfileDir(profilePath) {
				profiles = append(profiles, profilePath)
			}
		}
	}
	return profiles
}

func isFirefoxProfileDir(profilePath string) bool {
	for _, fileName := range []string{"prefs.js", "user.js"} {
		if _, err := os.Stat(filepath.Join(profilePath, fileName)); err == nil {
			return true
		}
	}
	return false
}

func firefoxProfilesRoot() string {
	homeDir := platform.GetConfig().HomeDir
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", "Firefox", "Profiles")
	case "windows":
		return filepath.Join(homeDir, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
	default:
		return ""
	}
}
