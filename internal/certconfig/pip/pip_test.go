package pip

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureOriginalCertFirstInstall(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (CertSetting, error) {
		return CertSetting{EnvVar: CertEnvVar, Path: "/corporate/pip-ca.pem"}, nil
	}

	got, err := ensureOriginalCertAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.EnvVar != CertEnvVar || got.Path != "/corporate/pip-ca.pem" {
		t.Fatalf("got %+v, want env=%q path=%q", got, CertEnvVar, "/corporate/pip-ca.pem")
	}

	data, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("saved file not written: %v", err)
	}
	parsed, err := parseSavedCertSetting(data)
	if err != nil {
		t.Fatalf("failed to parse saved state: %v", err)
	}
	if parsed.EnvVar != CertEnvVar || parsed.Path != "/corporate/pip-ca.pem" {
		t.Fatalf("saved file contains %+v, want env=%q path=%q", parsed, CertEnvVar, "/corporate/pip-ca.pem")
	}
}

func TestEnsureOriginalCertFirstInstallNothingSet(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (CertSetting, error) { return CertSetting{}, nil }

	got, err := ensureOriginalCertAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != (CertSetting{}) {
		t.Fatalf("got %+v, want empty setting", got)
	}
	if _, err := os.Stat(savedPath); err != nil {
		t.Fatalf("saved file not written for empty value: %v", err)
	}
}

func TestEnsureOriginalCertReinstallSkipsLookup(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	if err := os.WriteFile(savedPath, []byte("/saved/pip-ca.pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	lookupCalled := false
	lookup := func(_ context.Context) (CertSetting, error) {
		lookupCalled = true
		return CertSetting{EnvVar: CertEnvVar, Path: "/new-value/pip-ca.pem"}, nil
	}

	got, err := ensureOriginalCertAt(context.Background(), savedPath, lookup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.EnvVar != CertEnvVar || got.Path != "/saved/pip-ca.pem" {
		t.Fatalf("got %+v, want env=%q path=%q", got, CertEnvVar, "/saved/pip-ca.pem")
	}
	if lookupCalled {
		t.Fatal("lookup should not be called when saved file exists")
	}
}

func TestEnsureOriginalCertLookupError(t *testing.T) {
	savedPath := filepath.Join(t.TempDir(), "original.txt")
	lookup := func(_ context.Context) (CertSetting, error) {
		return CertSetting{}, errors.New("shell not found")
	}

	_, err := ensureOriginalCertAt(context.Background(), savedPath, lookup)
	if err == nil {
		t.Fatal("expected error when lookup fails")
	}
}

func TestParseSavedCertSettingLegacyFormat(t *testing.T) {
	got, err := parseSavedCertSetting([]byte("/legacy/pip-ca.pem\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.EnvVar != CertEnvVar || got.Path != "/legacy/pip-ca.pem" {
		t.Fatalf("got %+v, want env=%q path=%q", got, CertEnvVar, "/legacy/pip-ca.pem")
	}
}

func TestResolveBaseCACertBundleUsesOriginalWhenPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "base.pem")
	if err := os.WriteFile(path, []byte(mustCreateTestCertificatePEM(t, "pip-base")), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := resolveBaseCACertBundleAt(context.Background(), path, func(context.Context) string {
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

func TestResolveBaseCACertBundleFallsBackToCertifi(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certifi.pem")
	if err := os.WriteFile(path, []byte(mustCreateTestCertificatePEM(t, "certifi-base")), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := resolveBaseCACertBundleAt(context.Background(), "", func(context.Context) string {
		return path
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestResolveBaseCACertBundleFailsClosedWithoutBase(t *testing.T) {
	_, err := resolveBaseCACertBundleAt(context.Background(), "", func(context.Context) string {
		return ""
	})
	if err == nil {
		t.Fatal("expected error when no base bundle is available")
	}
}

func mustCreateTestCertificatePEM(t *testing.T, commonName string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}))
}
