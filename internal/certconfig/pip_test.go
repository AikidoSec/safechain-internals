package certconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureOriginalPipCertFirstInstall(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (string, error) {
		return "/corporate/pip-ca.pem", nil
	}

	got, err := ensureOriginalPipCertAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/corporate/pip-ca.pem" {
		t.Fatalf("got %q, want /corporate/pip-ca.pem", got)
	}

	data, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("saved file not written: %v", err)
	}
	if string(data) != "/corporate/pip-ca.pem" {
		t.Fatalf("saved file contains %q, want /corporate/pip-ca.pem", string(data))
	}
}

func TestEnsureOriginalPipCertFirstInstallNothingSet(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (string, error) { return "", nil }

	got, err := ensureOriginalPipCertAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty string", got)
	}
	if _, err := os.Stat(savedPath); err != nil {
		t.Fatalf("saved file not written for empty value: %v", err)
	}
}

func TestEnsureOriginalPipCertReinstallSkipsLookup(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	if err := os.WriteFile(savedPath, []byte("/saved/pip-ca.pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	lookupCalled := false
	lookup := func(_ context.Context) (string, error) {
		lookupCalled = true
		return "/new-value/pip-ca.pem", nil
	}

	got, err := ensureOriginalPipCertAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/saved/pip-ca.pem" {
		t.Fatalf("got %q, want /saved/pip-ca.pem", got)
	}
	if lookupCalled {
		t.Fatal("lookup should not be called when saved file exists")
	}
}

func TestEnsureOriginalPipCertLookupError(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (string, error) {
		return "", errors.New("shell not found")
	}

	_, err := ensureOriginalPipCertAt(context.Background(), savedPath, lookup)
	if err == nil {
		t.Fatal("expected error when lookup fails")
	}
}

func TestResolvePipBaseCACertBundleUsesOriginalWhenPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "base.pem")
	if err := os.WriteFile(path, []byte(mustCreateTestCertificatePEM(t, "pip-base")), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := resolvePipBaseCACertBundleAt(context.Background(), path, func(context.Context) string {
		t.Fatal("certifi lookup should not run when original bundle exists")
		return ""
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestResolvePipBaseCACertBundleFallsBackToCertifi(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certifi.pem")
	if err := os.WriteFile(path, []byte(mustCreateTestCertificatePEM(t, "certifi-base")), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := resolvePipBaseCACertBundleAt(context.Background(), "", func(context.Context) string {
		return path
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestResolvePipBaseCACertBundleFailsClosedWithoutBase(t *testing.T) {
	_, err := resolvePipBaseCACertBundleAt(context.Background(), "", func(context.Context) string {
		return ""
	})
	if err == nil {
		t.Fatal("expected error when no base bundle is available")
	}
}
