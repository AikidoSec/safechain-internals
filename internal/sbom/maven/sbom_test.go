package maven

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

func addPom(t *testing.T, repoDir, groupPath, artifactId, version string) {
	t.Helper()
	dir := filepath.Join(repoDir, groupPath, artifactId, version)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	filename := artifactId + "-" + version + ".pom"
	if err := os.WriteFile(filepath.Join(dir, filename), []byte("<project/>"), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSBOM(t *testing.T) {
	repoDir := t.TempDir()

	addPom(t, repoDir, "org/apache/commons", "commons-lang3", "3.14.0")
	addPom(t, repoDir, "com/google/guava", "guava", "33.0.0-jre")

	m := &Maven{}
	packages, err := m.SBOM(context.Background(), sbom.InstalledVersion{DataPath: repoDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}

	pkgByName := make(map[string]sbom.Package)
	for _, p := range packages {
		pkgByName[p.Name] = p
	}

	if p, ok := pkgByName["org.apache.commons:commons-lang3"]; !ok || p.Version != "3.14.0" {
		t.Errorf("expected org.apache.commons:commons-lang3 3.14.0, got %+v", p)
	}
	if p, ok := pkgByName["com.google.guava:guava"]; !ok || p.Version != "33.0.0-jre" {
		t.Errorf("expected com.google.guava:guava 33.0.0-jre, got %+v", p)
	}
}

func TestSBOMMultipleVersions(t *testing.T) {
	repoDir := t.TempDir()

	addPom(t, repoDir, "org/apache/commons", "commons-lang3", "3.13.0")
	addPom(t, repoDir, "org/apache/commons", "commons-lang3", "3.14.0")

	m := &Maven{}
	packages, err := m.SBOM(context.Background(), sbom.InstalledVersion{DataPath: repoDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 2 {
		t.Fatalf("expected 2 packages (both versions), got %d", len(packages))
	}

	versions := make(map[string]bool)
	for _, p := range packages {
		versions[p.Version] = true
	}

	if !versions["3.13.0"] || !versions["3.14.0"] {
		t.Errorf("expected versions 3.13.0 and 3.14.0, got %v", versions)
	}
}

func TestSBOMEmptyRepository(t *testing.T) {
	repoDir := t.TempDir()

	m := &Maven{}
	packages, err := m.SBOM(context.Background(), sbom.InstalledVersion{DataPath: repoDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(packages))
	}
}

func TestSBOMNonExistentRepository(t *testing.T) {
	m := &Maven{}
	packages, err := m.SBOM(context.Background(), sbom.InstalledVersion{DataPath: "/nonexistent/repo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if packages != nil {
		t.Fatalf("expected nil packages, got %v", packages)
	}
}

func TestSBOMSkipsMalformedPomFilenames(t *testing.T) {
	repoDir := t.TempDir()

	// Valid POM
	addPom(t, repoDir, "org/example", "valid-lib", "1.0.0")

	// Malformed: filename doesn't match artifactId-version.pom
	malformedDir := filepath.Join(repoDir, "org", "example", "broken-lib", "1.0.0")
	if err := os.MkdirAll(malformedDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(malformedDir, "wrong-name.pom"), []byte("<project/>"), 0644); err != nil {
		t.Fatal(err)
	}

	m := &Maven{}
	packages, err := m.SBOM(context.Background(), sbom.InstalledVersion{DataPath: repoDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package (malformed should be skipped), got %d", len(packages))
	}
	if packages[0].Name != "org.example:valid-lib" {
		t.Errorf("expected org.example:valid-lib, got %s", packages[0].Name)
	}
}

func TestSBOMSkipsNonPomFiles(t *testing.T) {
	repoDir := t.TempDir()

	addPom(t, repoDir, "org/example", "mylib", "1.0.0")

	// Add a .jar alongside the .pom - should be ignored
	jarPath := filepath.Join(repoDir, "org", "example", "mylib", "1.0.0", "mylib-1.0.0.jar")
	if err := os.WriteFile(jarPath, []byte("fake jar"), 0644); err != nil {
		t.Fatal(err)
	}

	m := &Maven{}
	packages, err := m.SBOM(context.Background(), sbom.InstalledVersion{DataPath: repoDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
}

func TestSBOMDeeplyNestedGroupId(t *testing.T) {
	repoDir := t.TempDir()

	addPom(t, repoDir, "io/github/openfeign/form", "feign-form", "4.0.0")

	m := &Maven{}
	packages, err := m.SBOM(context.Background(), sbom.InstalledVersion{DataPath: repoDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Name != "io.github.openfeign.form:feign-form" {
		t.Errorf("expected io.github.openfeign.form:feign-form, got %s", packages[0].Name)
	}
	if packages[0].Version != "4.0.0" {
		t.Errorf("expected version 4.0.0, got %s", packages[0].Version)
	}
}

func TestParseMavenVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{
			input:    "Apache Maven 3.9.6 (bc0240f3c744dd6b6ec2920b3cd08dcc295161ae)\nMaven home: /opt/homebrew/Cellar/maven/3.9.6/libexec",
			expected: "3.9.6",
		},
		{
			input:    "Apache Maven 3.8.1 (05c21c65bdfed0f71a2f2ada8b84da59348c4c5d)\n",
			expected: "3.8.1",
		},
		{
			input:    "Apache Maven 4.0.0-beta-4 (cecedd343002696d0abb50b32b541b8a6ba2883f)\n",
			expected: "4.0.0-beta-4",
		},
		{
			input:   "not maven output",
			wantErr: true,
		},
		{
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		result, err := parseMavenVersion(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseMavenVersion(%q) expected error, got %q", tt.input, result)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMavenVersion(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if result != tt.expected {
			t.Errorf("parseMavenVersion(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParsePackageFromPomPath(t *testing.T) {
	tests := []struct {
		name        string
		repoDir     string
		pomPath     string
		wantName    string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "standard artifact",
			repoDir:     "/home/user/.m2/repository",
			pomPath:     "/home/user/.m2/repository/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom",
			wantName:    "org.apache.commons:commons-lang3",
			wantVersion: "3.14.0",
		},
		{
			name:        "single-segment groupId",
			repoDir:     "/repo",
			pomPath:     "/repo/junit/junit/4.13.2/junit-4.13.2.pom",
			wantName:    "junit:junit",
			wantVersion: "4.13.2",
		},
		{
			name:    "path too short",
			repoDir: "/repo",
			pomPath: "/repo/foo/bar.pom",
			wantErr: true,
		},
		{
			name:    "filename mismatch",
			repoDir: "/repo",
			pomPath: "/repo/org/example/lib/1.0.0/wrong-1.0.0.pom",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, err := parsePackageFromPomPath(tt.repoDir, tt.pomPath)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got %+v", pkg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pkg.Name != tt.wantName {
				t.Errorf("name = %q, want %q", pkg.Name, tt.wantName)
			}
			if pkg.Version != tt.wantVersion {
				t.Errorf("version = %q, want %q", pkg.Version, tt.wantVersion)
			}
		})
	}
}
