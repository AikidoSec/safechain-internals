package pip

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/certconfig/shared"
	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const (
	CertEnvVar          = "PIP_CERT"
	RequestsCABundleEnvVar = "REQUESTS_CA_BUNDLE"
	SSLCertFileEnvVar      = "SSL_CERT_FILE"
)

func findSystemCABundle(ctx context.Context) string {
	for _, pythonBin := range []string{"python3", "python"} {
		pythonPath, err := exec.LookPath(pythonBin)
		if err != nil {
			continue
		}
		out, err := platform.RunAsCurrentUserWithPathEnv(ctx, pythonPath, "-c", "import certifi; print(certifi.where())")
		if err != nil {
			continue
		}
		path := strings.TrimSpace(out)
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// certifi is not installed — fall back to the path reported by Python's
	// stdlib ssl module (available in every Python installation).
	for _, pythonBin := range []string{"python3", "python"} {
		pythonPath, err := exec.LookPath(pythonBin)
		if err != nil {
			continue
		}
		out, err := platform.RunAsCurrentUserWithPathEnv(ctx, pythonPath, "-c",
			"import ssl; p = ssl.get_default_verify_paths(); print(p.cafile or p.openssl_cafile or '')")
		if err != nil {
			continue
		}
		path := strings.TrimSpace(out)
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func extractMarkedCertSetting(output string) CertSetting {
	return parseCertSettingString(shared.ExtractMarkedCertValue(output))
}

func parseCertSettingString(value string) CertSetting {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return CertSetting{}
	}

	envVar, path, ok := strings.Cut(trimmed, ":")
	if !ok {
		return CertSetting{
			EnvVar: CertEnvVar,
			Path:   trimmed,
		}
	}

	switch envVar {
	case CertEnvVar, RequestsCABundleEnvVar, SSLCertFileEnvVar:
		return CertSetting{
			EnvVar: envVar,
			Path:   strings.TrimSpace(path),
		}
	default:
		return CertSetting{
			EnvVar: CertEnvVar,
			Path:   trimmed,
		}
	}
}
