package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadAndValidatePEMBundleValidCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.pem")
	pemData := mustCreateTestCertificatePEM(t, "test-cert")
	if err := os.WriteFile(path, []byte(pemData), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadAndValidatePEMBundle(path)
	if err != nil {
		t.Fatalf("ReadAndValidatePEMBundle failed: %v", err)
	}

	if !strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Fatalf("expected certificate PEM in output, got %q", got)
	}
}

func TestReadAndValidatePEMBundleRejectsNonPEMContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadAndValidatePEMBundle(path)
	if err == nil {
		t.Fatal("expected error for non-PEM content")
	}
}

func TestReadAndValidatePEMBundleRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.pem")
	link := filepath.Join(dir, "link.pem")

	pemData := mustCreateTestCertificatePEM(t, "symlink-test")
	if err := os.WriteFile(target, []byte(pemData), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	_, err := ReadAndValidatePEMBundle(link)
	if err == nil {
		t.Fatal("expected error for symlinked bundle")
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
