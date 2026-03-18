package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type extensionToUninstall struct {
	extensionId string
	profileDir  string
}

func UninstallBlockedExtensions(ctx context.Context, extensionsToUninstall []string) {
	log.Printf("Chrome extension uninstall check (homeDir=%s)", platform.GetConfig().HomeDir)
	// killBrowsers(ctx)

	installations, err := findInstallations(ctx)
	if err != nil {
		log.Printf("Failed to find Chrome installations for extension uninstall check: %v", err)
		return
	}
	if len(installations) == 0 {
		log.Printf("Chrome extension uninstall check: no installations found")
	}

	var toUninstall []extensionToUninstall

	for _, inst := range installations {
		profiles := findProfilesWithExtensions(inst.DataPath)
		for _, profile := range profiles {
			profileDir := filepath.Join(inst.DataPath, profile)
			extDir := filepath.Join(profileDir, "Extensions")
			entries, err := os.ReadDir(extDir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				id := strings.ToLower(entry.Name())
				if slices.Contains(extensionsToUninstall, id) {
					toUninstall = append(toUninstall, extensionToUninstall{
						extensionId: entry.Name(),
						profileDir:  profileDir,
					})
				}
			}
		}
	}

	if len(toUninstall) > 0 {
		for _, ext := range toUninstall {
			log.Printf("Uninstalling blocked Chrome extension %s from %s", ext.extensionId, ext.profileDir)
			if err := removeExtension(ext.profileDir, ext.extensionId); err != nil {
				log.Printf("Failed to remove Chrome extension %s: %v", ext.extensionId, err)
			} else {
				log.Printf("Successfully removed Chrome extension %s", ext.extensionId)
			}

		}
	}
}

// func killBrowsers(ctx context.Context) {
// 	switch runtime.GOOS {
// 	case "darwin":
// 		homeDir := platform.GetConfig().HomeDir
// 		for _, b := range getBrowsers(homeDir) {
// 			for _, bin := range b.bins {
// 				_ = exec.CommandContext(ctx, "pkill", "-9", "-f", bin).Run()
// 			}
// 		}
// 	case "windows":
// 		for _, exe := range []string{"chrome.exe", "brave.exe", "msedge.exe", "chromium.exe"} {
// 			_ = exec.CommandContext(ctx, "taskkill", "/F", "/IM", exe).Run()
// 		}
// 	}
// }

func removeExtension(profileDir, extensionId string) error {
	if err := os.RemoveAll(filepath.Join(profileDir, "Extensions", extensionId)); err != nil {
		return err
	}
	_ = os.RemoveAll(filepath.Join(profileDir, "Sync Extension Settings", extensionId))
	_ = removeFromPrefsFile(filepath.Join(profileDir, "Preferences"), extensionId)
	return removeFromPrefsFile(filepath.Join(profileDir, "Secure Preferences"), extensionId)
}

func removeFromPrefsFile(prefsPath, extensionId string) error {
	data, err := os.ReadFile(prefsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var prefs map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&prefs); err != nil {
		return err
	}

	// Delete prefs["extensions"]["settings"][extensionId]
	if ext, ok := prefs["extensions"].(map[string]interface{}); ok {
		if settings, ok := ext["settings"].(map[string]interface{}); ok {
			delete(settings, extensionId)
		}
	}

	// Delete prefs["protection"]["macs"]["extensions"]["settings"][extensionId]
	if protection, ok := prefs["protection"].(map[string]interface{}); ok {
		if macs, ok := protection["macs"].(map[string]interface{}); ok {
			if ext, ok := macs["extensions"].(map[string]interface{}); ok {
				if settings, ok := ext["settings"].(map[string]interface{}); ok {
					delete(settings, extensionId)
				}
				if settings, ok := ext["settings_encrypted_hash"].(map[string]interface{}); ok {
					delete(settings, extensionId)
				}
			}
		}
	}

	out, err := json.Marshal(prefs)
	if err != nil {
		return err
	}

	return os.WriteFile(prefsPath, out, 0600)
}
