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
	lookup := func(_ context.Context) (pipCertSetting, error) {
		return pipCertSetting{EnvVar: pipCertEnvVar, Path: "/corporate/pip-ca.pem"}, nil
	}

	got, err := ensureOriginalPipCertAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.EnvVar != pipCertEnvVar || got.Path != "/corporate/pip-ca.pem" {
		t.Fatalf("got %+v, want env=%q path=%q", got, pipCertEnvVar, "/corporate/pip-ca.pem")
	}

	data, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("saved file not written: %v", err)
	}
	parsed, err := parseSavedPipCertSetting(data)
	if err != nil {
		t.Fatalf("failed to parse saved state: %v", err)
	}
	if parsed.EnvVar != pipCertEnvVar || parsed.Path != "/corporate/pip-ca.pem" {
		t.Fatalf("saved file contains %+v, want env=%q path=%q", parsed, pipCertEnvVar, "/corporate/pip-ca.pem")
	}
}

func TestEnsureOriginalPipCertFirstInstallNothingSet(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (pipCertSetting, error) { return pipCertSetting{}, nil }

	got, err := ensureOriginalPipCertAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != (pipCertSetting{}) {
		t.Fatalf("got %+v, want empty setting", got)
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
	lookup := func(_ context.Context) (pipCertSetting, error) {
		lookupCalled = true
		return pipCertSetting{EnvVar: pipCertEnvVar, Path: "/new-value/pip-ca.pem"}, nil
	}

	got, err := ensureOriginalPipCertAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.EnvVar != pipCertEnvVar || got.Path != "/saved/pip-ca.pem" {
		t.Fatalf("got %+v, want env=%q path=%q", got, pipCertEnvVar, "/saved/pip-ca.pem")
	}
	if lookupCalled {
		t.Fatal("lookup should not be called when saved file exists")
	}
}

func TestEnsureOriginalPipCertLookupError(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (pipCertSetting, error) {
		return pipCertSetting{}, errors.New("shell not found")
	}

	_, err := ensureOriginalPipCertAt(context.Background(), savedPath, lookup)
	if err == nil {
		t.Fatal("expected error when lookup fails")
	}
}

func TestParseSavedPipCertSettingLegacyFormat(t *testing.T) {
	got, err := parseSavedPipCertSetting([]byte("/legacy/pip-ca.pem\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.EnvVar != pipCertEnvVar || got.Path != "/legacy/pip-ca.pem" {
		t.Fatalf("got %+v, want env=%q path=%q", got, pipCertEnvVar, "/legacy/pip-ca.pem")
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
