package skills

import (
	"path/filepath"
	"testing"
)

func TestFindBinaries(t *testing.T) {
	// findBinaries derives skills paths from npm locations; verify the binary name is correct.
	binary := binaryName()
	if binary == "" {
		t.Fatal("binaryName() returned empty string")
	}
	if filepath.Ext(binary) == ".cmd" && filepath.Base(binary) != "skills.cmd" {
		t.Errorf("unexpected windows binary name: %q", binary)
	}
}

func TestParseSkillsLsOutputEmpty(t *testing.T) {
	entries, err := parseSkillsLsOutput("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseSkillsLsOutputSingle(t *testing.T) {
	output := `[{"name":"skill-finder","path":"/home/alice/.agents/skills/skill-finder","scope":"global","agents":["Claude Code"]}]`

	entries, err := parseSkillsLsOutput(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Name != "skill-finder" {
		t.Errorf("unexpected name: %q", entries[0].Name)
	}
	if entries[0].Scope != "global" {
		t.Errorf("unexpected scope: %q", entries[0].Scope)
	}
	if len(entries[0].Agents) != 1 || entries[0].Agents[0] != "Claude Code" {
		t.Errorf("unexpected agents: %v", entries[0].Agents)
	}
}

func TestParseSkillsLsOutputMultiple(t *testing.T) {
	output := `[
		{"name":"skill-finder","path":"/home/alice/.agents/skills/skill-finder","scope":"global","agents":["Claude Code","Codex"]},
		{"name":"commit","path":"/home/alice/.agents/skills/commit","scope":"global","agents":["Claude Code"]}
	]`

	entries, err := parseSkillsLsOutput(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestParseSkillsLsOutputInvalidJSON(t *testing.T) {
	_, err := parseSkillsLsOutput("not valid json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
