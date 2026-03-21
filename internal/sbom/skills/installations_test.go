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
	want := []globalSkillsDir{
		{variant: "codex", path: filepath.Join(homeDir, ".codex", "skills")},
		{variant: "claude", path: filepath.Join(homeDir, ".claude", "skills")},
		{variant: "cursor", path: filepath.Join(homeDir, ".cursor", "skills")},
		{variant: "windsurf", path: filepath.Join(homeDir, ".windsurf", "skills")},
		{variant: "gemini", path: filepath.Join(homeDir, ".gemini", "skills")},
		{variant: "kiro", path: filepath.Join(homeDir, ".kiro", "skills")},
		{variant: "opencode", path: filepath.Join(homeDir, ".opencode", "skills")},
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

	found := findKnownLockFiles([]globalSkillsDir{{variant: "codex", path: skillsDir}})

	if len(found) != 1 {
		t.Fatalf("expected 1 lock file, got %d", len(found))
	}
	if found[0].path != lockPath {
		t.Errorf("expected %q, got %q", lockPath, found[0].path)
	}
	if found[0].variant != "codex" {
		t.Errorf("expected variant %q, got %q", "codex", found[0].variant)
	}
}

func TestFindKnownLockFilesFindsMultiple(t *testing.T) {
	root := t.TempDir()

	var roots []globalSkillsDir
	for _, tc := range []struct {
		variant string
		dirname string
	}{
		{variant: "codex", dirname: ".codex"},
		{variant: "claude", dirname: ".claude"},
	} {
		dir := filepath.Join(root, tc.dirname, "skills")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		writeLockFile(t, dir, `{"version": 1, "skills": {}}`)
		roots = append(roots, globalSkillsDir{variant: tc.variant, path: dir})
	}

	found := findKnownLockFiles(roots)

	if len(found) != 2 {
		t.Fatalf("expected 2 lock files, got %d", len(found))
	}
}
