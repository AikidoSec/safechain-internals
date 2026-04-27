package ingress

import "testing"

func TestAdd_PreservesNonBlockedStatusFromExistingEvent(t *testing.T) {
	store := &eventStore{
		events: []BlockEvent{
			{
				ID:   "existing-1",
				TsMs: 500,
				Artifact: Artifact{
					Product:     "npm",
					PackageName: "evil-pkg",
				},
				Status: "allowed",
			},
		},
	}

	got := store.Add(BlockEvent{
		TsMs: 1000,
		Artifact: Artifact{
			Product:     "npm",
			PackageName: "evil-pkg",
		},
		BlockReason: "malware",
	})

	if got.Status != "allowed" {
		t.Fatalf("expected status to be preserved as %q, got %q", "allowed", got.Status)
	}
}

func TestMergeChromeBlockIfDuplicate_MergesMatchingArtifact(t *testing.T) {
	store := &eventStore{
		events: []BlockEvent{
			{
				ID:   "existing",
				TsMs: 1000,
				Artifact: Artifact{
					Product:        "chrome",
					PackageName:    "aikido-safechain",
					PackageVersion: "1.0.0",
					DisplayName:    "Aikido SafeChain",
				},
				BlockReason: "blocked by policy",
				Status:      "blocked",
				Count:       1,
			},
		},
	}

	merged := store.MergeChromeBlockIfDuplicate(BlockEvent{
		TsMs: 2000,
		Artifact: Artifact{
			Product:        "chrome",
			PackageName:    "aikido-safechain",
			PackageVersion: "1.0.0",
			DisplayName:    "Aikido SafeChain",
		},
		BlockReason: "blocked by policy",
	})

	if !merged {
		t.Fatalf("expected duplicate chrome block to be merged")
	}
	if got := len(store.events); got != 1 {
		t.Fatalf("expected 1 stored event, got %d", got)
	}
	if got := store.events[0].Count; got != 2 {
		t.Fatalf("expected count 2 after merge, got %d", got)
	}
	if got := store.events[0].TsMs; got != 2000 {
		t.Fatalf("expected timestamp to be updated to 2000, got %d", got)
	}
}

func TestMergeChromeBlockIfDuplicate_DoesNotMergeDifferentArtifact(t *testing.T) {
	store := &eventStore{
		events: []BlockEvent{
			{
				ID:   "existing",
				TsMs: 1000,
				Artifact: Artifact{
					Product:        "chrome",
					PackageName:    "aikido-safechain",
					PackageVersion: "1.0.0",
				},
				BlockReason: "blocked by policy",
				Status:      "blocked",
				Count:       1,
			},
		},
	}

	merged := store.MergeChromeBlockIfDuplicate(BlockEvent{
		TsMs: 3000,
		Artifact: Artifact{
			Product:        "chrome",
			PackageName:    "another-package",
			PackageVersion: "1.0.0",
		},
		BlockReason: "blocked by policy",
	})

	if merged {
		t.Fatalf("expected non-duplicate chrome block not to merge")
	}
	if got := len(store.events); got != 1 {
		t.Fatalf("expected store length to remain 1, got %d", got)
	}
	if got := store.events[0].Count; got != 1 {
		t.Fatalf("expected count to remain 1, got %d", got)
	}
	if got := store.events[0].TsMs; got != 1000 {
		t.Fatalf("expected timestamp to remain 1000, got %d", got)
	}
}
