//go:build windows

package pip

import (
	"strings"
	"testing"
)

func TestRestoreWindowsEnvScriptRestoresRequestsBundle(t *testing.T) {
	script := restoreWindowsEnvScript(CertSetting{
		EnvVar: RequestsCABundleEnvVar,
		Path:   `C:\corp\bundle.pem`,
	})

	if !strings.Contains(script, "[Environment]::SetEnvironmentVariable('PIP_CERT', $null, 'User')") {
		t.Fatalf("expected PIP_CERT to be cleared, got %q", script)
	}
	if !strings.Contains(script, "[Environment]::SetEnvironmentVariable('REQUESTS_CA_BUNDLE', 'C:\\corp\\bundle.pem', 'User')") {
		t.Fatalf("expected REQUESTS_CA_BUNDLE restore, got %q", script)
	}
	if strings.Contains(script, "SSL_CERT_FILE") {
		t.Fatalf("did not expect SSL_CERT_FILE mutation, got %q", script)
	}
}
