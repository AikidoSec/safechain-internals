package chrome

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

type extensionManifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

var versionPattern = regexp.MustCompile(`\d+\.\d+[\d.]*`)

func runBrowserVersion(ctx context.Context, binaryPath string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := platform.RunAsCurrentUserWithPathEnv(quietCtx, binaryPath, "--version")
	if err != nil {
		return "", err
	}

	return parseVersionOutput(strings.TrimSpace(output)), nil
}

// parseVersionOutput extracts the version number from browser --version output.
// e.g. "Google Chrome 120.0.6099.109" -> "120.0.6099.109"
func parseVersionOutput(output string) string {
	lines := strings.SplitN(output, "\n", 2)
	if len(lines) == 0 {
		return ""
	}
	line := strings.TrimSpace(lines[0])

	return versionPattern.FindString(line)
}

// readExtensionVersions reads all installed versions of a Chrome extension
// and returns a Package for each valid version directory.
func readExtensionVersions(extDir string, extensionID string) []sbom.Package {
	versionDirs := findVersionDirs(extDir)

	var packages []sbom.Package
	for _, dir := range versionDirs {
		versionPath := filepath.Join(extDir, dir)

		data, err := os.ReadFile(filepath.Join(versionPath, "manifest.json"))
		if err != nil {
			log.Printf("Skipping version dir %s: %v", dir, err)
			continue
		}

		var manifest extensionManifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			log.Printf("Skipping version dir %s: %v", dir, err)
			continue
		}

		if manifest.Version == "" {
			continue
		}

		name := manifest.Name
		if strings.HasPrefix(name, "__MSG_") && strings.HasSuffix(name, "__") {
			name = resolveLocalizedName(versionPath, name)
		}
		if name == "" {
			name = extensionID
		}

		packages = append(packages, sbom.Package{
			Id:      extensionID,
			Name:    name,
			Version: manifest.Version,
		})
	}

	return packages
}

// resolveLocalizedName reads the _locales messages files to resolve __MSG_key__ strings.
// Only English locales are tried to ensure consistent output regardless of machine settings.
func resolveLocalizedName(versionDir string, name string) string {
	nameKey := strings.TrimPrefix(name, "__MSG_")
	nameKey = strings.TrimSuffix(nameKey, "__")

	for _, locale := range []string{"en", "en_US", "en_GB"} {
		messagesPath := filepath.Join(versionDir, "_locales", locale, "messages.json")
		data, err := os.ReadFile(messagesPath)
		if err != nil {
			continue
		}

		var messages map[string]struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(data, &messages); err != nil {
			continue
		}

		for key, value := range messages {
			if strings.EqualFold(key, nameKey) && value.Message != "" {
				return value.Message
			}
		}
	}

	return ""
}

// findVersionDirs returns all version subdirectories within a Chrome extension directory.
// Version dirs look like "1.2.3_0"; dirs starting with "_" or "." are skipped.
func findVersionDirs(extDir string) []string {
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return nil
	}

	var dirs []string
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), "_") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		manifestPath := filepath.Join(extDir, entry.Name(), "manifest.json")
		if _, err := os.Stat(manifestPath); err == nil {
			dirs = append(dirs, entry.Name())
		}
	}

	return dirs
}
