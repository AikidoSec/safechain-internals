package skills

import (
	"testing"
)

func TestPackagesFromEntries(t *testing.T) {
	entries := []skillsEntry{
		{Name: "skill-finder", Path: "/home/alice/.agents/skills/skill-finder", Scope: "global", Agents: []string{"Claude Code"}},
	}

	packages := packagesFromEntries(entries)

	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	if packages[0].Id != "skill-finder" {
		t.Errorf("expected id 'skill-finder', got %q", packages[0].Id)
	}
	if packages[0].Name != "skill-finder" {
		t.Errorf("expected name 'skill-finder', got %q", packages[0].Name)
	}
	if packages[0].Version != "" {
		t.Errorf("unexpected version %q", packages[0].Version)
	}
}

func TestPackagesFromEntriesEmpty(t *testing.T) {
	packages := packagesFromEntries(nil)
	if len(packages) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(packages))
	}
}

func TestPackagesFromEntriesMultiple(t *testing.T) {
	entries := []skillsEntry{
		{Name: "skill-finder", Scope: "global"},
		{Name: "commit", Scope: "global"},
	}

	packages := packagesFromEntries(entries)

	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}

	byID := make(map[string]bool)
	for _, p := range packages {
		byID[p.Id] = true
	}
	if !byID["skill-finder"] || !byID["commit"] {
		t.Errorf("unexpected packages: %v", packages)
	}
}
