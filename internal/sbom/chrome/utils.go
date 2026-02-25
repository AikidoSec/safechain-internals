package chrome

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

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

type extensionManifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func readLatestExtension(extDir string, extensionID string) (*sbom.Package, error) {
	versionDir, err := findLatestVersionDir(extDir)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(versionDir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest.json: %w", err)
	}

	var manifest extensionManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest.json: %w", err)
	}

	if manifest.Version == "" {
		return nil, fmt.Errorf("missing version in manifest.json")
	}

	name := manifest.Name
	if strings.HasPrefix(name, "__MSG_") && strings.HasSuffix(name, "__") {
		if resolved := resolveLocalizedName(versionDir, name); resolved != "" {
			name = resolved
		}
	}

	if name == "" {
		name = extensionID
	}

	return &sbom.Package{
		Id:      extensionID,
		Name:    name,
		Version: manifest.Version,
	}, nil
}

// resolveLocalizedName reads the _locales messages files to resolve __MSG_key__ strings.
// Only English locales are tried to ensure consistent output regardless of machine settings.
func resolveLocalizedName(versionDir string, msgRef string) string {
	key := strings.TrimPrefix(msgRef, "__MSG_")
	key = strings.TrimSuffix(key, "__")

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

		for k, v := range messages {
			if strings.EqualFold(k, key) && v.Message != "" {
				return v.Message
			}
		}
	}

	return ""
}

// findLatestVersionDir finds the version subdirectory with the highest version
// within a Chrome extension directory. Version dirs look like "1.2.3_0".
func findLatestVersionDir(extDir string) (string, error) {
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return "", fmt.Errorf("failed to read extension directory: %w", err)
	}

	var versionDirs []string
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), "_") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		manifestPath := filepath.Join(extDir, entry.Name(), "manifest.json")
		if _, err := os.Stat(manifestPath); err == nil {
			versionDirs = append(versionDirs, entry.Name())
		}
	}

	if len(versionDirs) == 0 {
		return "", fmt.Errorf("no valid version directories found")
	}

	sort.Strings(versionDirs)
	latest := versionDirs[len(versionDirs)-1]

	return filepath.Join(extDir, latest), nil
}
