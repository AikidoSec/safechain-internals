package chrome

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

// Chrome persists extension state in two JSON files at the root of each profile:
//   - Preferences:        regular user-installed extensions
//   - Secure Preferences: policy/force-installed extensions
type extensionSetting struct {
	State          *int  `json:"state"`
	DisableReasons []int `json:"disable_reasons"`
}

type preferencesFile struct {
	Extensions struct {
		Settings map[string]extensionSetting `json:"settings"`
	} `json:"extensions"`
}

// readProfileExtensionStates returns a map from extension ID to true (enabled)
// or false (disabled) for extensions explicitly listed in the profile's
// Preferences or Secure Preferences. Secure Preferences wins on conflict.
func readProfileExtensionStates(profileDir string) map[string]bool {
	states := map[string]bool{}

	for _, name := range []string{"Preferences", "Secure Preferences"} {
		path := filepath.Join(profileDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var prefs preferencesFile
		if err := json.Unmarshal(data, &prefs); err != nil {
			log.Printf("Failed to parse %s at %s: %v", name, profileDir, err)
			continue
		}

		for id, setting := range prefs.Extensions.Settings {
			if len(setting.DisableReasons) > 0 {
				states[id] = false
				continue
			}
			if setting.State != nil {
				states[id] = *setting.State == 1
			}
		}
	}

	return states
}
