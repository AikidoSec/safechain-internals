//go:build windows

package certconfig

import (
	"strings"
	"testing"
)

func TestRestoreWindowsPipEnvScriptRestoresRequestsBundle(t *testing.T) {
	script := restoreWindowsPipEnvScript(pipCertSetting{
		EnvVar: requestsCABundleEnvVar,
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
