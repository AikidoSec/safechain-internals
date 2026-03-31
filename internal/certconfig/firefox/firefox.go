package firefox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	"github.com/AikidoSec/safechain-internals/internal/certconfig/shared"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

var managedBlockFormat = shared.ManagedBlockFormat{
	StartMarker: "// aikido-endpoint-cert-config-start",
	EndMarker:   "// aikido-endpoint-cert-config-end",
}

type Configurator struct{}

func New() *Configurator {
	return &Configurator{}
}

func (c *Configurator) Name() string {
	return "firefox"
}

func (c *Configurator) Install(_ context.Context) error {
	for _, profile := range profiles() {
		path := filepath.Join(profile, "user.js")
		body := `user_pref("security.enterprise_roots.enabled", true);`
		if err := shared.WriteManagedBlock(path, body, 0o644, managedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

func (c *Configurator) Uninstall(_ context.Context) error {
	for _, profile := range profiles() {
		path := filepath.Join(profile, "user.js")
		if err := utils.RemoveManagedBlock(path, 0o644, managedBlockFormat.StartMarker, managedBlockFormat.EndMarker); err != nil {
			return err
		}
	}
	return nil
}

func profiles() []string {
	root := profilesRoot()
	if root == "" {
		return nil
	}

	if _, err := os.Stat(root); err != nil {
		return nil
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profilePath := filepath.Join(root, entry.Name())
		if isProfileDir(profilePath) {
			result = append(result, profilePath)
		}
	}
	return result
}

func isProfileDir(profilePath string) bool {
	for _, fileName := range []string{"prefs.js", "user.js"} {
		if _, err := os.Stat(filepath.Join(profilePath, fileName)); err == nil {
			return true
		}
	}
	return false
}

func profilesRoot() string {
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
