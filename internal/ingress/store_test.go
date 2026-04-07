package ingress

import "testing"

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
