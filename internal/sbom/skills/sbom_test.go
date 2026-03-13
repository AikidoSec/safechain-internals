package skills

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

func writeLockFile(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, lockFileName)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSBOM(t *testing.T) {
	dir := t.TempDir()
	lockPath := writeLockFile(t, dir, `{
		"version": 1,
		"skills": {
			"fun-brainstorming": {
				"source": "roin-orca/skills",
				"sourceType": "github",
				"computedHash": "b1873510f9c511f65db575ffb5721b6caa8bac4cf4f81515618b339186f6ca56"
			}
		}
	}`)

	s := &SkillsSh{}
	packages, err := s.SBOM(context.Background(), sbom.InstalledVersion{DataPath: lockPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}

	pkg := packages[0]
	if pkg.Id != "roin-orca/skills/fun-brainstorming" {
		t.Errorf("expected id 'roin-orca/skills/fun-brainstorming', got %q", pkg.Id)
	}
	if pkg.Name != "fun-brainstorming" {
		t.Errorf("expected name 'fun-brainstorming', got %q", pkg.Name)
	}
	if pkg.Version != "b1873510f9c511f65db575ffb5721b6caa8bac4cf4f81515618b339186f6ca56" {
		t.Errorf("unexpected version %q", pkg.Version)
	}
}

func TestSBOMMultipleSkills(t *testing.T) {
	dir := t.TempDir()
	lockPath := writeLockFile(t, dir, `{
		"version": 1,
		"skills": {
			"skill-one": {
				"source": "owner/repo",
				"sourceType": "github",
				"computedHash": "aaaa"
			},
			"skill-two": {
				"source": "owner/repo",
				"sourceType": "github",
				"computedHash": "bbbb"
			}
		}
	}`)

	s := &SkillsSh{}
	packages, err := s.SBOM(context.Background(), sbom.InstalledVersion{DataPath: lockPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}

	byID := make(map[string]sbom.Package)
	for _, p := range packages {
		byID[p.Id] = p
	}

	if p, ok := byID["owner/repo/skill-one"]; !ok || p.Version != "aaaa" {
		t.Errorf("unexpected skill-one: %+v", p)
	}
	if p, ok := byID["owner/repo/skill-two"]; !ok || p.Version != "bbbb" {
		t.Errorf("unexpected skill-two: %+v", p)
	}
}

func TestSBOMSkipsEntriesWithEmptySource(t *testing.T) {
	dir := t.TempDir()
	lockPath := writeLockFile(t, dir, `{
		"version": 1,
		"skills": {
			"valid-skill": {
				"source": "owner/repo",
				"sourceType": "github",
				"computedHash": "cccc"
			},
			"broken-skill": {
				"source": "",
				"sourceType": "github",
				"computedHash": "dddd"
			}
		}
	}`)

	s := &SkillsSh{}
	packages, err := s.SBOM(context.Background(), sbom.InstalledVersion{DataPath: lockPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("expected 1 package (broken-skill skipped), got %d", len(packages))
	}
	if packages[0].Id != "owner/repo/valid-skill" {
		t.Errorf("unexpected id %q", packages[0].Id)
	}
}

func TestSBOMEmptySkills(t *testing.T) {
	dir := t.TempDir()
	lockPath := writeLockFile(t, dir, `{"version": 1, "skills": {}}`)

	s := &SkillsSh{}
	packages, err := s.SBOM(context.Background(), sbom.InstalledVersion{DataPath: lockPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(packages) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(packages))
	}
}

func TestSBOMInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	lockPath := writeLockFile(t, dir, `not valid json`)

	s := &SkillsSh{}
	_, err := s.SBOM(context.Background(), sbom.InstalledVersion{DataPath: lockPath})
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSBOMFileNotFound(t *testing.T) {
	s := &SkillsSh{}
	_, err := s.SBOM(context.Background(), sbom.InstalledVersion{DataPath: "/nonexistent/skills-lock.json"})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

