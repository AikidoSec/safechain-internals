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

func TestReadLatestExtension(t *testing.T) {
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

	pkg, err := readLatestExtension(extDir, "test-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkg.Name != "Test Extension" {
		t.Errorf("expected name 'Test Extension', got %s", pkg.Name)
	}
	if pkg.Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %s", pkg.Version)
	}
	if pkg.Id != "test-id" {
		t.Errorf("expected id 'test-id', got %s", pkg.Id)
	}
}

func TestReadLatestExtensionMissingVersion(t *testing.T) {
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

	_, err := readLatestExtension(extDir, "test-id")
	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

func TestReadLatestExtensionFallbackToID(t *testing.T) {
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

	pkg, err := readLatestExtension(extDir, "fallback-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkg.Name != "fallback-id" {
		t.Errorf("expected name to fall back to extension ID 'fallback-id', got %s", pkg.Name)
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

	name := resolveLocalizedName(versionDir, "en", "__MSG_appName__")
	if name != "My Cool Extension" {
		t.Errorf("expected 'My Cool Extension', got %s", name)
	}
}

func TestResolveLocalizedNameNotFound(t *testing.T) {
	versionDir := t.TempDir()
	name := resolveLocalizedName(versionDir, "en", "__MSG_missing__")
	if name != "" {
		t.Errorf("expected empty string, got %s", name)
	}
}

func TestFindLatestVersionDir(t *testing.T) {
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

	result, err := findLatestVersionDir(extDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Base(result) != "2.0.0_0" {
		t.Errorf("expected '2.0.0_0', got %s", filepath.Base(result))
	}
}

func TestFindLatestVersionDirSkipsMetadata(t *testing.T) {
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

	result, err := findLatestVersionDir(extDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Base(result) != "1.0.0_0" {
		t.Errorf("expected '1.0.0_0', got %s", filepath.Base(result))
	}
}

func TestFindLatestVersionDirEmpty(t *testing.T) {
	extDir := t.TempDir()
	_, err := findLatestVersionDir(extDir)
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
}
