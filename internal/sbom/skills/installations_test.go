package skills

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestKnownGlobalSkillsRoots(t *testing.T) {
	homeDir := filepath.Join(string(filepath.Separator), "home", "alice")

	got := knownGlobalSkillsRoots(homeDir)
	want := []string{
		filepath.Join(homeDir, ".codex", "skills"),
		filepath.Join(homeDir, ".claude", "skills"),
		filepath.Join(homeDir, ".cursor", "skills"),
		filepath.Join(homeDir, ".windsurf", "skills"),
		filepath.Join(homeDir, ".gemini", "skills"),
		filepath.Join(homeDir, ".kiro", "skills"),
		filepath.Join(homeDir, ".opencode", "skills"),
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected roots:\nwant=%v\ngot=%v", want, got)
	}
}

func TestFindKnownLockFilesFindsExactLockFile(t *testing.T) {
	root := t.TempDir()

	skillsDir := filepath.Join(root, ".codex", "skills")
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		t.Fatal(err)
	}
	lockPath := writeLockFile(t, skillsDir, `{"version": 1, "skills": {}}`)

	found := findKnownLockFiles([]string{skillsDir})

	if len(found) != 1 {
		t.Fatalf("expected 1 lock file, got %d", len(found))
	}
	if found[0] != lockPath {
		t.Errorf("expected %q, got %q", lockPath, found[0])
	}
}

func TestFindKnownLockFilesFindsMultiple(t *testing.T) {
	root := t.TempDir()

	var roots []string
	for _, name := range []string{".codex", ".claude"} {
		dir := filepath.Join(root, name, "skills")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		writeLockFile(t, dir, `{"version": 1, "skills": {}}`)
		roots = append(roots, dir)
	}

	found := findKnownLockFiles(roots)

	if len(found) != 2 {
		t.Fatalf("expected 2 lock files, got %d", len(found))
	}
}
