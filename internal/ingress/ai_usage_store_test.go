package ingress

import "testing"

func TestAiUsageEventStoreAddAssignsStableIDAndReportsNew(t *testing.T) {
	store := &aiUsageEventStore{}

	stored, isNew := store.Add(AiUsageEvent{
		TsMs:     100,
		Provider: "anthropic",
		Model:    "claude-3-5-sonnet-20241022",
	})

	want := "ai-usage-anthropic-claude-3-5-sonnet-20241022"
	if stored.ID != want {
		t.Fatalf("expected stable id %q, got %q", want, stored.ID)
	}
	if !isNew {
		t.Fatalf("expected first observation to report isNew=true")
	}
	if stored.TsMs != 100 {
		t.Fatalf("expected stored ts_ms=100, got %d", stored.TsMs)
	}
}

func TestAiUsageEventStoreAddCollapsesSameModelAndRefreshesTimestamp(t *testing.T) {
	store := &aiUsageEventStore{}

	first, firstIsNew := store.Add(AiUsageEvent{TsMs: 100, Provider: "anthropic", Model: "claude-opus-4-7"})
	second, secondIsNew := store.Add(AiUsageEvent{TsMs: 250, Provider: "anthropic", Model: "claude-opus-4-7"})
	third, thirdIsNew := store.Add(AiUsageEvent{TsMs: 400, Provider: "anthropic", Model: "claude-opus-4-7"})

	if !firstIsNew {
		t.Fatalf("expected first call to report isNew=true")
	}
	if secondIsNew || thirdIsNew {
		t.Fatalf("expected repeats to report isNew=false, got second=%v third=%v", secondIsNew, thirdIsNew)
	}
	if first.ID != second.ID || second.ID != third.ID {
		t.Fatalf("expected stable aggregate id, got %q / %q / %q", first.ID, second.ID, third.ID)
	}
	if len(store.List()) != 1 {
		t.Fatalf("expected one aggregate event, got %d", len(store.List()))
	}
	if third.TsMs != 400 {
		t.Fatalf("expected ts_ms to refresh to 400, got %d", third.TsMs)
	}
}

func TestAiUsageEventStoreAddSeparatesEntriesPerModel(t *testing.T) {
	store := &aiUsageEventStore{}

	store.Add(AiUsageEvent{TsMs: 100, Provider: "anthropic", Model: "claude-opus-4-7"})
	store.Add(AiUsageEvent{TsMs: 200, Provider: "anthropic", Model: "claude-haiku-4-5"})

	if len(store.List()) != 2 {
		t.Fatalf("expected one aggregate event per model, got %d", len(store.List()))
	}
}

func TestAiUsageEventStoreAddSeparatesEntriesPerProvider(t *testing.T) {
	store := &aiUsageEventStore{}

	store.Add(AiUsageEvent{TsMs: 100, Provider: "anthropic", Model: "shared-name"})
	store.Add(AiUsageEvent{TsMs: 200, Provider: "openai", Model: "shared-name"})

	if len(store.List()) != 2 {
		t.Fatalf("expected one aggregate event per provider, got %d", len(store.List()))
	}
}

func TestServerSnapshotAiUsageReturnsCopyAndDoesNotClear(t *testing.T) {
	s := &Server{aiUsageStore: &aiUsageEventStore{}}

	s.aiUsageStore.Add(AiUsageEvent{TsMs: 100, Provider: "anthropic", Model: "claude-opus-4-7"})
	s.aiUsageStore.Add(AiUsageEvent{TsMs: 200, Provider: "anthropic", Model: "claude-opus-4-7"})

	snap1 := s.SnapshotAiUsage()
	if len(snap1) != 1 {
		t.Fatalf("expected one row in snapshot, got %d", len(snap1))
	}
	if snap1[0].TsMs != 200 {
		t.Fatalf("expected ts_ms=200 (latest), got %d", snap1[0].TsMs)
	}

	// Mutating the returned slice must not affect the store.
	snap1[0].TsMs = 999
	snap2 := s.SnapshotAiUsage()
	if snap2[0].TsMs != 200 {
		t.Fatalf("snapshot must be a copy; store was mutated to ts_ms=%d", snap2[0].TsMs)
	}

	// A second snapshot after a flush-equivalent call must still see the data —
	// the store is intentionally not cleared.
	if len(snap2) != 1 {
		t.Fatalf("expected store to retain data after snapshot, got %d rows", len(snap2))
	}
}
