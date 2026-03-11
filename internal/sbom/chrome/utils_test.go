package chrome

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseVersionOutput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Google Chrome 120.0.6099.109", "120.0.6099.109"},
		{"Brave Browser 1.62.156 Chromium: 121.0.6167.139", "1.62.156"},
		{"Microsoft Edge 120.0.2210.133", "120.0.2210.133"},
		{"Chromium 121.0.6167.139", "121.0.6167.139"},
		{"120.0.6099.109", "120.0.6099.109"},
		{"", ""},
	}

	for _, tt := range tests {
		result := parseVersionOutput(tt.input)
		if result != tt.expected {
			t.Errorf("parseVersionOutput(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestReadExtensionVersions(t *testing.T) {
	extDir := t.TempDir()
	versionDir := filepath.Join(extDir, "1.0.0_0")
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "manifest.json"), []byte(`{
		"name": "Test Extension",
		"version": "1.0.0"
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	packages := readExtensionVersions(extDir, "test-id")
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "Test Extension" {
		t.Errorf("expected name 'Test Extension', got %s", packages[0].Name)
	}
	if packages[0].Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %s", packages[0].Version)
	}
	if packages[0].Id != "test-id" {
		t.Errorf("expected id 'test-id', got %s", packages[0].Id)
	}
}

func TestReadExtensionVersionsMultiple(t *testing.T) {
	extDir := t.TempDir()
	for _, v := range []struct{ dir, version string }{
		{"1.0.0_0", "1.0.0"},
		{"2.0.0_0", "2.0.0"},
	} {
		dir := filepath.Join(extDir, v.dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		manifest := `{"name": "Test Extension", "version": "` + v.version + `"}`
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0644); err != nil {
			t.Fatal(err)
		}
	}

	packages := readExtensionVersions(extDir, "test-id")
	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}

	versions := make(map[string]bool)
	for _, p := range packages {
		versions[p.Version] = true
	}
	if !versions["1.0.0"] || !versions["2.0.0"] {
		t.Errorf("expected versions 1.0.0 and 2.0.0, got %v", versions)
	}
}

func TestReadExtensionVersionsSkipsMissingVersion(t *testing.T) {
	extDir := t.TempDir()
	versionDir := filepath.Join(extDir, "1.0.0_0")
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "manifest.json"), []byte(`{
		"name": "No Version"
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	packages := readExtensionVersions(extDir, "test-id")
	if len(packages) != 0 {
		t.Errorf("expected 0 packages for missing version, got %d", len(packages))
	}
}

func TestReadExtensionVersionsFallbackToID(t *testing.T) {
	extDir := t.TempDir()
	versionDir := filepath.Join(extDir, "1.0.0_0")
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "manifest.json"), []byte(`{
		"version": "1.0.0"
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	packages := readExtensionVersions(extDir, "fallback-id")
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "fallback-id" {
		t.Errorf("expected name to fall back to extension ID 'fallback-id', got %s", packages[0].Name)
	}
}

func TestResolveLocalizedName(t *testing.T) {
	versionDir := t.TempDir()
	localeDir := filepath.Join(versionDir, "_locales", "en")
	if err := os.MkdirAll(localeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localeDir, "messages.json"), []byte(`{
		"appName": { "message": "My Cool Extension" }
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	name := resolveLocalizedName(versionDir, "__MSG_appName__")
	if name != "My Cool Extension" {
		t.Errorf("expected 'My Cool Extension', got %s", name)
	}
}

func TestResolveLocalizedNameNotFound(t *testing.T) {
	versionDir := t.TempDir()
	name := resolveLocalizedName(versionDir, "__MSG_missing__")
	if name != "" {
		t.Errorf("expected empty string, got %s", name)
	}
}

func TestFindVersionDirs(t *testing.T) {
	extDir := t.TempDir()
	for _, ver := range []string{"1.0.0_0", "2.0.0_0"} {
		dir := filepath.Join(extDir, ver)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{}`), 0644); err != nil {
			t.Fatal(err)
		}
	}

	dirs := findVersionDirs(extDir)
	if len(dirs) != 2 {
		t.Fatalf("expected 2 version dirs, got %d", len(dirs))
	}
}

func TestFindVersionDirsSkipsMetadata(t *testing.T) {
	extDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(extDir, "_metadata"), 0755); err != nil {
		t.Fatal(err)
	}
	versionDir := filepath.Join(extDir, "1.0.0_0")
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "manifest.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	dirs := findVersionDirs(extDir)
	if len(dirs) != 1 {
		t.Fatalf("expected 1 version dir, got %d", len(dirs))
	}
	if dirs[0] != "1.0.0_0" {
		t.Errorf("expected '1.0.0_0', got %s", dirs[0])
	}
}

func TestFindVersionDirsEmpty(t *testing.T) {
	extDir := t.TempDir()
	dirs := findVersionDirs(extDir)
	if len(dirs) != 0 {
		t.Errorf("expected 0 version dirs, got %d", len(dirs))
	}
}
