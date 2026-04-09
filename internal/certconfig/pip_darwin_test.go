//go:build darwin

package certconfig

import (
	"strings"
	"testing"
)

func TestNewPipTrustConfiguratorManagedBlockContent(t *testing.T) {
	const bundle = "/some/bundle.pem"
	cfg := newPipTrustConfigurator(bundle).(*darwinPipTrustConfigurator)

	// Every shell target should export all required vars.
	requiredPosix := []string{
		`export PIP_CERT=`,
		`export REQUESTS_CA_BUNDLE=`,
		`export POETRY_CERTIFICATES_PYPI_CERT=`,
		`export UV_NATIVE_TLS=true`,
		bundle,
	}
	requiredFish := []string{
		`set -gx PIP_CERT`,
		`set -gx REQUESTS_CA_BUNDLE`,
		`set -gx POETRY_CERTIFICATES_PYPI_CERT`,
		`set -gx UV_NATIVE_TLS true`,
		bundle,
	}

	for _, target := range cfg.targets {
		isFish := strings.HasSuffix(target.path, "config.fish")
		required := requiredPosix
		if isFish {
			required = requiredFish
		}
		for _, want := range required {
			if !strings.Contains(target.body, want) {
				t.Errorf("shell target %s: body missing %q\ngot:\n%s", target.path, want, target.body)
			}
		}
	}
}

func TestNewPipTrustConfiguratorDoesNotSetSSLCertFile(t *testing.T) {
	cfg := newPipTrustConfigurator("/some/bundle.pem").(*darwinPipTrustConfigurator)
	for _, target := range cfg.targets {
		if strings.Contains(target.body, "SSL_CERT_FILE") {
			t.Errorf("shell target %s: body must not set SSL_CERT_FILE (too broad)\ngot:\n%s", target.path, target.body)
		}
	}
}
