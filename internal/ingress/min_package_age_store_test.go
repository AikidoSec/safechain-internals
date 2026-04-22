package ingress

import "testing"

func TestMinPackageAgeEventStoreAddAssignsIDAndCopiesVersions(t *testing.T) {
	store := &minPackageAgeEventStore{}

	input := MinPackageAgeEvent{
		TsMs:      123,
		Ecosystem: "vscode",
	}

	stored := store.Add(input)
	if stored.ID != "min-package-age-suppressed-vscode" {
		t.Fatalf("expected stable id %q, got %q", "min-package-age-suppressed-vscode", stored.ID)
	}
	if stored.Title != "vscode package versions suppressed" || stored.Message == "" {
		t.Fatalf("expected generic title and message to be populated")
	}
	if stored.Ecosystem != "vscode" {
		t.Fatalf("expected ecosystem to be stored, got %q", stored.Ecosystem)
	}

	got, ok := store.Get(stored.ID)
	if !ok {
		t.Fatalf("expected stored event to exist")
	}
	if got.Title != stored.Title || got.Message != stored.Message {
		t.Fatalf("expected stored event to preserve generic copy")
	}
}

func TestMinPackageAgeEventStoreAddUpdatesExistingEntryInsteadOfDuplicating(t *testing.T) {
	store := &minPackageAgeEventStore{}

	first := store.Add(MinPackageAgeEvent{TsMs: 123, Ecosystem: "vscode"})
	second := store.Add(MinPackageAgeEvent{TsMs: 456, Ecosystem: "vscode"})

	if first.ID != second.ID {
		t.Fatalf("expected stable aggregate id, got %q and %q", first.ID, second.ID)
	}
	if len(store.List()) != 1 {
		t.Fatalf("expected a single aggregate event, got %d", len(store.List()))
	}
	if second.TsMs != 456 {
		t.Fatalf("expected timestamp to be refreshed, got %d", second.TsMs)
	}
}

func TestMinPackageAgeEventStoreAddCreatesOneEntryPerEcosystem(t *testing.T) {
	store := &minPackageAgeEventStore{}

	first := store.Add(MinPackageAgeEvent{TsMs: 123, Ecosystem: "vscode"})
	second := store.Add(MinPackageAgeEvent{TsMs: 456, Ecosystem: "npm"})

	if first.ID == second.ID {
		t.Fatalf("expected different ids per ecosystem, got %q", first.ID)
	}
	if len(store.List()) != 2 {
		t.Fatalf("expected one aggregate event per ecosystem, got %d", len(store.List()))
	}
}
