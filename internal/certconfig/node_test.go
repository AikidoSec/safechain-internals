package certconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureOriginalNodeExtraCACertsFirstInstall(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (string, error) {
		return "/corporate/ca.pem", nil
	}

	got, err := ensureOriginalNodeExtraCACertsAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/corporate/ca.pem" {
		t.Fatalf("got %q, want /corporate/ca.pem", got)
	}

	data, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("saved file not written: %v", err)
	}
	if string(data) != "/corporate/ca.pem" {
		t.Fatalf("saved file contains %q, want /corporate/ca.pem", string(data))
	}
}

func TestEnsureOriginalNodeExtraCACertsFirstInstallNothingSet(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (string, error) { return "", nil }

	got, err := ensureOriginalNodeExtraCACertsAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty string", got)
	}

	// Empty string must still be saved so reinstall knows we already ran.
	if _, err := os.Stat(savedPath); err != nil {
		t.Fatalf("saved file not written for empty value: %v", err)
	}
}

func TestEnsureOriginalNodeExtraCACertsReinstallSkipsLookup(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	if err := os.WriteFile(savedPath, []byte("/saved/ca.pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	lookupCalled := false
	lookup := func(_ context.Context) (string, error) {
		lookupCalled = true
		return "/new-value/ca.pem", nil
	}

	got, err := ensureOriginalNodeExtraCACertsAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/saved/ca.pem" {
		t.Fatalf("got %q, want /saved/ca.pem", got)
	}
	if lookupCalled {
		t.Fatal("lookup should not be called when saved file exists")
	}
}

func TestEnsureOriginalNodeExtraCACertsTrimsSavedWhitespace(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	if err := os.WriteFile(savedPath, []byte("  /trimmed/ca.pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ensureOriginalNodeExtraCACertsAt(context.Background(), savedPath, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/trimmed/ca.pem" {
		t.Fatalf("got %q, want /trimmed/ca.pem", got)
	}
}

func TestEnsureOriginalNodeExtraCACertsTrimsLookupWhitespace(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (string, error) { return "  /padded/ca.pem\n", nil }

	got, err := ensureOriginalNodeExtraCACertsAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/padded/ca.pem" {
		t.Fatalf("got %q, want /padded/ca.pem", got)
	}
}

func TestEnsureOriginalNodeExtraCACertsLookupError(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (string, error) {
		return "", errors.New("shell not found")
	}

	_, err := ensureOriginalNodeExtraCACertsAt(context.Background(), savedPath, lookup)
	if err == nil {
		t.Fatal("expected error when lookup fails")
	}
}
