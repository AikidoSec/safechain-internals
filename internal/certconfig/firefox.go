package certconfig

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

var firefoxManagedBlockFormat = managedBlockFormat{
	startMarker: "// aikido-endpoint-cert-config-start",
	endMarker:   "// aikido-endpoint-cert-config-end",
}

type firefoxConfigurator struct{}

func newFirefoxConfigurator() Configurator {
	return &firefoxConfigurator{}
}

func (c *firefoxConfigurator) Name() string {
	return "firefox"
}

func (c *firefoxConfigurator) Install(_ context.Context) error {
	body := `user_pref("security.enterprise_roots.enabled", true);`
	for _, userJS := range firefoxUserJSPaths() {
		if err := writeManagedBlock(userJS, body, 0o644, firefoxManagedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

func (c *firefoxConfigurator) NeedsRepair(_ context.Context) bool {
	for _, userJS := range firefoxUserJSPaths() {
		present, err := hasManagedBlock(userJS, firefoxManagedBlockFormat)
		if err != nil || !present {
			return true
		}
	}
	return false
}

func (c *firefoxConfigurator) Uninstall(_ context.Context) error {
	for _, userJS := range firefoxUserJSPaths() {
		if err := utils.RemoveManagedBlock(userJS, 0o644, firefoxManagedBlockFormat.startMarker, firefoxManagedBlockFormat.endMarker); err != nil {
			return err
		}
	}
	return nil
}

func firefoxUserJSPaths() []string {
	profiles := firefoxProfiles()
	paths := make([]string, len(profiles))
	for i, profile := range profiles {
		paths[i] = filepath.Join(profile, "user.js")
	}
	return paths
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
		profilePath := filepath.Join(profilesRoot, entry.Name())
		if isFirefoxProfileDir(profilePath) {
			profiles = append(profiles, profilePath)
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
