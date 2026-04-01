package certconfig

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

type managedBlockFormat struct {
	startMarker string
	endMarker   string
}

const aikidoCertMarker = "AIKIDO_CERT="

const (
	pipCertEnvVar          = "PIP_CERT"
	requestsCABundleEnvVar = "REQUESTS_CA_BUNDLE"
	sslCertFileEnvVar      = "SSL_CERT_FILE"
)

func buildManagedBlock(body string, format managedBlockFormat, newline string) string {
	return format.startMarker + newline + body + newline + format.endMarker + newline
}

func detectNewline(content string) string {
	if strings.Contains(content, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

func hasTrailingNewline(content string) bool {
	return strings.HasSuffix(content, "\n") || strings.HasSuffix(content, "\r\n")
}

func writeManagedBlock(path string, body string, perm os.FileMode, format managedBlockFormat) error {
	content := ""
	if data, err := os.ReadFile(path); err == nil {
		content = string(data)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	newline := detectNewline(content)

	stripped, _, err := utils.RemoveMarkedBlock(content, format.startMarker, format.endMarker)
	if err != nil {
		return fmt.Errorf("failed to remove existing managed block in %s: %w", path, err)
	}

	if stripped != "" && !hasTrailingNewline(stripped) {
		stripped += newline
	}

	body = strings.ReplaceAll(body, "\r\n", "\n")
	if newline != "\n" {
		body = strings.ReplaceAll(body, "\n", newline)
	}

	return os.WriteFile(path, []byte(stripped+buildManagedBlock(body, format, newline)), perm)
}

// extractMarkedCertValue scans output for a line starting with aikidoCertMarker
// and returns the value after it. This tolerates arbitrary text before or after
// the marker line, which interactive shells may produce.
func extractMarkedCertValue(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		if strings.HasPrefix(line, aikidoCertMarker) {
			return strings.TrimSpace(line[len(aikidoCertMarker):])
		}
	}
	return ""
}

func findSystemPipCABundle(ctx context.Context) string {
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

func extractMarkedPipCertSetting(output string) pipCertSetting {
	return parsePipCertSettingString(extractMarkedCertValue(output))
}

func parsePipCertSettingString(value string) pipCertSetting {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return pipCertSetting{}
	}

	envVar, path, ok := strings.Cut(trimmed, ":")
	if !ok {
		return pipCertSetting{
			EnvVar: pipCertEnvVar,
			Path:   trimmed,
		}
	}

	switch envVar {
	case pipCertEnvVar, requestsCABundleEnvVar, sslCertFileEnvVar:
		return pipCertSetting{
			EnvVar: envVar,
			Path:   strings.TrimSpace(path),
		}
	default:
		return pipCertSetting{
			EnvVar: pipCertEnvVar,
			Path:   trimmed,
		}
	}
}
