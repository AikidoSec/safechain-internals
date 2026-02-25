package chrome

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

// setupBrowserDataDir creates a Chrome-like data directory with a Default profile.
func setupBrowserDataDir(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	extDir := filepath.Join(tmpDir, "Default", "Extensions")
	if err := os.MkdirAll(extDir, 0755); err != nil {
		t.Fatal(err)
	}
	return tmpDir
}

func addExtension(t *testing.T, dataDir, profile, extensionID, version, manifest string) {
	t.Helper()
	versionDir := version + "_0"
	extDir := filepath.Join(dataDir, profile, "Extensions", extensionID, versionDir)
	if err := os.MkdirAll(extDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extDir, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSBOM(t *testing.T) {
	dataDir := setupBrowserDataDir(t)

	addExtension(t, dataDir, "Default", "abcdefghijklmnopqrstuvwxyzabcdef", "1.0.0", `{
		"name": "Adobe Acrobat",
		"version": "1.0.0",
		"manifest_version": 3
	}`)
	addExtension(t, dataDir, "Default", "fedcbazyxwvutsrqponmlkjihgfedcba", "2.0.0", `{
		"name": "Google Docs Offline",
		"version": "2.0.0",
		"manifest_version": 3
	}`)

	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{
		Variant:  "chrome",
		DataPath: dataDir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}

	pkgByID := make(map[string]sbom.Package)
	for _, p := range packages {
		pkgByID[p.Id] = p
	}

	if p, ok := pkgByID["abcdefghijklmnopqrstuvwxyzabcdef"]; !ok || p.Name != "Adobe Acrobat" || p.Version != "1.0.0" {
		t.Errorf("expected Adobe Acrobat 1.0.0, got %+v", p)
	}
	if p, ok := pkgByID["fedcbazyxwvutsrqponmlkjihgfedcba"]; !ok || p.Name != "Google Docs Offline" || p.Version != "2.0.0" {
		t.Errorf("expected Google Docs Offline 2.0.0, got %+v", p)
	}
}

func TestSBOMReportsAllVersions(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "fedcbazyxwvutsrqponmlkjihgfedcba"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{
		"name": "Test Extension",
		"version": "1.0.0",
		"manifest_version": 3
	}`)
	addExtension(t, dataDir, "Default", extID, "2.0.0", `{
		"name": "Test Extension",
		"version": "2.0.0",
		"manifest_version": 3
	}`)

	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{DataPath: dataDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 2 {
		t.Fatalf("expected 2 packages (all versions), got %d", len(packages))
	}

	versions := make(map[string]bool)
	for _, p := range packages {
		if p.Id != extID {
			t.Errorf("expected ID %s, got %s", extID, p.Id)
		}
		versions[p.Version] = true
	}
	if !versions["1.0.0"] || !versions["2.0.0"] {
		t.Errorf("expected versions 1.0.0 and 2.0.0, got %v", versions)
	}
}

func TestSBOMDeduplicatesAcrossProfiles(t *testing.T) {
	dataDir := t.TempDir()
	extID := "sharedextensionid12345678901234"

	for _, profile := range []string{"Default", "Profile 1"} {
		if err := os.MkdirAll(filepath.Join(dataDir, profile, "Extensions"), 0755); err != nil {
			t.Fatal(err)
		}
	}

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{
		"name": "Shared Extension",
		"version": "1.0.0",
		"manifest_version": 3
	}`)
	addExtension(t, dataDir, "Profile 1", extID, "1.0.0", `{
		"name": "Shared Extension",
		"version": "1.0.0",
		"manifest_version": 3
	}`)

	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{DataPath: dataDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package (deduplicated), got %d", len(packages))
	}
	if packages[0].Id != extID {
		t.Errorf("expected ID %s, got %s", extID, packages[0].Id)
	}
	if packages[0].Name != "Shared Extension" {
		t.Errorf("expected 'Shared Extension', got %s", packages[0].Name)
	}
}

func TestSBOMLocalizedName(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "localizedextension1234567890abcd"

	versionDir := filepath.Join(dataDir, "Default", "Extensions", extID, "1.0.0_0")
	localeDir := filepath.Join(versionDir, "_locales", "en")
	if err := os.MkdirAll(localeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "manifest.json"), []byte(`{
		"name": "__MSG_appName__",
		"version": "1.0.0",
		"default_locale": "en",
		"manifest_version": 3
	}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localeDir, "messages.json"), []byte(`{
		"appName": {
			"message": "My Cool Extension"
		}
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{DataPath: dataDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Id != extID {
		t.Errorf("expected ID %s, got %s", extID, packages[0].Id)
	}
	if packages[0].Name != "My Cool Extension" {
		t.Errorf("expected 'My Cool Extension', got %s", packages[0].Name)
	}
}

func TestSBOMFallsBackToExtensionIDWhenNameEmpty(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "noname_extension_id_1234567890ab"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{
		"version": "1.0.0",
		"manifest_version": 3
	}`)

	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{DataPath: dataDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Id != extID {
		t.Errorf("expected ID %s, got %s", extID, packages[0].Id)
	}
	if packages[0].Name != extID {
		t.Errorf("expected fallback name to extension ID %s, got %s", extID, packages[0].Name)
	}
}

func TestSBOMSkipsHiddenAndInvalid(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extBaseDir := filepath.Join(dataDir, "Default", "Extensions")

	if err := os.MkdirAll(filepath.Join(extBaseDir, ".hidden"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(extBaseDir, "nomanifest", "1.0.0_0"), 0755); err != nil {
		t.Fatal(err)
	}

	addExtension(t, dataDir, "Default", "validextension123456789012345678", "1.0.0", `{
		"name": "Valid Extension",
		"version": "1.0.0",
		"manifest_version": 3
	}`)

	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{DataPath: dataDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "Valid Extension" {
		t.Errorf("expected 'Valid Extension', got %s", packages[0].Name)
	}
}

func TestSBOMSkipsMetadataDir(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "someextensionid12345678901234567"
	extDir := filepath.Join(dataDir, "Default", "Extensions", extID)

	if err := os.MkdirAll(filepath.Join(extDir, "_metadata"), 0755); err != nil {
		t.Fatal(err)
	}

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Test", "version": "1.0.0"}`)

	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{DataPath: dataDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", packages[0].Version)
	}
}

func TestSBOMMissingVersion(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	addExtension(t, dataDir, "Default", "extensionwithoutversion123456789", "1.0.0", `{
		"name": "No Version"
	}`)

	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{DataPath: dataDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 0 {
		t.Fatalf("expected 0 packages (missing version should be skipped), got %d", len(packages))
	}
}

func TestSBOMEmptyExtensionsDir(t *testing.T) {
	dataDir := setupBrowserDataDir(t)

	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{DataPath: dataDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(packages))
	}
}

func TestFindProfilesWithExtensions(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(tmpDir, "Default", "Extensions"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "Profile 1", "Extensions"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "Profile 2"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "Crashpad", "Extensions"), 0755); err != nil {
		t.Fatal(err)
	}

	profiles := findProfilesWithExtensions(tmpDir)

	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d: %v", len(profiles), profiles)
	}

	profileMap := make(map[string]bool)
	for _, p := range profiles {
		profileMap[p] = true
	}

	if !profileMap["Default"] {
		t.Error("expected 'Default' profile")
	}
	if !profileMap["Profile 1"] {
		t.Error("expected 'Profile 1' profile")
	}
}

func TestFindProfilesNonExistentDir(t *testing.T) {
	profiles := findProfilesWithExtensions("/nonexistent/path")
	if len(profiles) != 0 {
		t.Fatalf("expected 0 profiles, got %d", len(profiles))
	}
}

