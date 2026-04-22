package chrome

import (
	"context"
	"encoding/json"
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

// writePreferences writes a Chrome Preferences (or Secure Preferences) file at
// the root of the given profile. states maps extension IDs to their Chrome
// state value (1 = enabled, 0 = disabled, etc.).
func writePreferences(t *testing.T, dataDir, profile, filename string, states map[string]int) {
	t.Helper()
	settings := map[string]map[string]any{}
	for id, state := range states {
		settings[id] = map[string]any{"state": state}
	}
	payload := map[string]any{
		"extensions": map[string]any{
			"settings": settings,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, profile, filename)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func writePreferencesWithDisableReasons(
	t *testing.T,
	dataDir, profile, filename string,
	disableReasons map[string][]int,
) {
	t.Helper()
	settings := map[string]map[string]any{}
	for id, reasons := range disableReasons {
		settings[id] = map[string]any{
			"disable_reasons": reasons,
		}
	}
	payload := map[string]any{
		"extensions": map[string]any{
			"settings": settings,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, profile, filename)
	if err := os.WriteFile(path, data, 0644); err != nil {
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
		Ecosystem: "chrome",
		Variant:   "chrome",
		DataPath:  dataDir,
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

func runSBOM(t *testing.T, dataDir string) []sbom.Package {
	t.Helper()
	c := &ChromeExtensions{}
	packages, err := c.SBOM(context.Background(), sbom.InstalledVersion{DataPath: dataDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return packages
}

func TestSBOMReportsEnabledStateFromPreferences(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "enabledextensionid1234567890abcd"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Enabled", "version": "1.0.0"}`)
	writePreferences(t, dataDir, "Default", "Preferences", map[string]int{extID: 1})

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "enabled" {
		t.Errorf("expected State 'enabled', got %q", packages[0].State)
	}
}

func TestSBOMReportsDisabledStateFromPreferences(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "disabledextensionid123456789abcd"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Disabled", "version": "1.0.0"}`)
	writePreferences(t, dataDir, "Default", "Preferences", map[string]int{extID: 0})

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "disabled" {
		t.Errorf("expected State 'disabled', got %q", packages[0].State)
	}
}

func TestSBOMStateDefaultsToEnabledWhenPreferencesMissing(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "noprefsextensionid1234567890abcd"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "No Prefs", "version": "1.0.0"}`)

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "enabled" {
		t.Errorf("expected State 'enabled' (fail-open), got %q", packages[0].State)
	}
}

func TestSBOMStateDefaultsToEnabledWhenEntryMissing(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "unlistedextensionid1234567890abc"
	otherID := "otherextensionid12345678901234ab"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Unlisted", "version": "1.0.0"}`)
	writePreferences(t, dataDir, "Default", "Preferences", map[string]int{otherID: 0})

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "enabled" {
		t.Errorf("expected State 'enabled' (entry missing), got %q", packages[0].State)
	}
}

func TestSBOMStateEnabledInOneProfileWins(t *testing.T) {
	dataDir := t.TempDir()
	extID := "sharedextensionid12345678901234a"

	for _, profile := range []string{"Default", "Profile 1"} {
		if err := os.MkdirAll(filepath.Join(dataDir, profile, "Extensions"), 0755); err != nil {
			t.Fatal(err)
		}
	}

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Shared", "version": "1.0.0"}`)
	addExtension(t, dataDir, "Profile 1", extID, "1.0.0", `{"name": "Shared", "version": "1.0.0"}`)
	writePreferences(t, dataDir, "Default", "Preferences", map[string]int{extID: 0})
	writePreferences(t, dataDir, "Profile 1", "Preferences", map[string]int{extID: 1})

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package (deduplicated), got %d", len(packages))
	}
	if packages[0].State != "enabled" {
		t.Errorf("expected State 'enabled' (enabled in any profile wins), got %q", packages[0].State)
	}
}

func TestSBOMStateDisabledInAllProfiles(t *testing.T) {
	dataDir := t.TempDir()
	extID := "offeverywhereid123456789012345ab"

	for _, profile := range []string{"Default", "Profile 1"} {
		if err := os.MkdirAll(filepath.Join(dataDir, profile, "Extensions"), 0755); err != nil {
			t.Fatal(err)
		}
	}

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Off", "version": "1.0.0"}`)
	addExtension(t, dataDir, "Profile 1", extID, "1.0.0", `{"name": "Off", "version": "1.0.0"}`)
	writePreferences(t, dataDir, "Default", "Preferences", map[string]int{extID: 0})
	writePreferences(t, dataDir, "Profile 1", "Preferences", map[string]int{extID: 0})

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "disabled" {
		t.Errorf("expected State 'disabled', got %q", packages[0].State)
	}
}

func TestSBOMStateReadFromSecurePreferences(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "policyinstalledextid12345678901"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Policy", "version": "1.0.0"}`)
	writePreferences(t, dataDir, "Default", "Secure Preferences", map[string]int{extID: 0})

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "disabled" {
		t.Errorf("expected State 'disabled' from Secure Preferences, got %q", packages[0].State)
	}
}

func TestSBOMStateReadFromSecurePreferencesDisableReasons(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "disabledbyreasons12345678901234"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Disabled", "version": "1.0.0"}`)
	writePreferencesWithDisableReasons(t, dataDir, "Default", "Secure Preferences", map[string][]int{
		extID: {1},
	})

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "disabled" {
		t.Errorf("expected State 'disabled' from disable_reasons, got %q", packages[0].State)
	}
}

func TestSBOMStateSecurePreferencesOverridesPreferences(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "overrideextid1234567890123456789"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Override", "version": "1.0.0"}`)
	writePreferences(t, dataDir, "Default", "Preferences", map[string]int{extID: 1})
	writePreferences(t, dataDir, "Default", "Secure Preferences", map[string]int{extID: 0})

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "disabled" {
		t.Errorf("expected State 'disabled' (Secure Preferences wins), got %q", packages[0].State)
	}
}

func TestSBOMStateBlocklistedTreatedAsDisabled(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "blocklistedextid1234567890abcdef"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Blocked", "version": "1.0.0"}`)
	// Chrome uses state values like 3 (blocklisted) or 6 (blocked by policy)
	// for extensions that are installed but not runnable. Anything other
	// than 1 collapses to "disabled" in the SBOM.
	writePreferences(t, dataDir, "Default", "Preferences", map[string]int{extID: 3})

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "disabled" {
		t.Errorf("expected State 'disabled' for blocklisted extension, got %q", packages[0].State)
	}
}

func TestSBOMStateMalformedPreferencesFailsOpen(t *testing.T) {
	dataDir := setupBrowserDataDir(t)
	extID := "malformedprefsextid123456789abcd"

	addExtension(t, dataDir, "Default", extID, "1.0.0", `{"name": "Malformed", "version": "1.0.0"}`)
	if err := os.WriteFile(filepath.Join(dataDir, "Default", "Preferences"), []byte("{not json"), 0644); err != nil {
		t.Fatal(err)
	}

	packages := runSBOM(t, dataDir)
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].State != "enabled" {
		t.Errorf("expected State 'enabled' (fail-open), got %q", packages[0].State)
	}
}
