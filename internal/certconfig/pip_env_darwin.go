//go:build darwin

package certconfig

import (
	"context"
	"os/exec"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

// pipCertShellLookups tries login and interactive startup files separately
// because they are sourced in different modes:
//   - Login non-interactive (-lc): ~/.zprofile or ~/.bash_profile
//   - Interactive non-login (-ic): ~/.zshrc or ~/.bashrc
//   - fish --login: ~/.config/fish/config.fish
//
// Each command wraps the result in a unique marker so shell startup noise does
// not contaminate the discovered Python CA bundle override.
var pipCertShellLookups = []shellLookup{
	{"zsh", []string{"-lc", buildPOSIXPipCertLookupScript()}},
	{"zsh", []string{"-ic", buildPOSIXPipCertLookupScript()}},
	{"bash", []string{"-lc", buildPOSIXPipCertLookupScript()}},
	{"bash", []string{"-ic", buildPOSIXPipCertLookupScript()}},
	{"fish", []string{"--login", "-c", buildFishPipCertLookupScript()}},
}

func buildPOSIXPipCertLookupScript() string {
	return strings.Join([]string{
		`if [ -n "${PIP_CERT:-}" ]; then`,
		`  printf 'AIKIDO_CERT=PIP_CERT:%s\n' "$PIP_CERT"`,
		`elif [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then`,
		`  printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' "$REQUESTS_CA_BUNDLE"`,
		`elif [ -n "${SSL_CERT_FILE:-}" ]; then`,
		`  printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' "$SSL_CERT_FILE"`,
		`elif [ -n "${POETRY_CERTIFICATES_PYPI_CERT:-}" ]; then`,
		`  printf 'AIKIDO_CERT=POETRY_CERTIFICATES_PYPI_CERT:%s\n' "$POETRY_CERTIFICATES_PYPI_CERT"`,
		`fi`,
	}, "\n")
}

func buildFishPipCertLookupScript() string {
	return strings.Join([]string{
		`if set -q PIP_CERT`,
		`  printf 'AIKIDO_CERT=PIP_CERT:%s\n' $PIP_CERT`,
		`else if set -q REQUESTS_CA_BUNDLE`,
		`  printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' $REQUESTS_CA_BUNDLE`,
		`else if set -q SSL_CERT_FILE`,
		`  printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' $SSL_CERT_FILE`,
		`else if set -q POETRY_CERTIFICATES_PYPI_CERT`,
		`  printf 'AIKIDO_CERT=POETRY_CERTIFICATES_PYPI_CERT:%s\n' $POETRY_CERTIFICATES_PYPI_CERT`,
		`end`,
	}, "\n")
}

func runPipCertLookup(ctx context.Context) (pipCertSetting, error) {
	for _, lookup := range pipCertShellLookups {
		shellPath, err := exec.LookPath(lookup.name)
		if err != nil {
			continue
		}
		out, err := platform.RunAsCurrentUserWithPathEnv(ctx, shellPath, lookup.args...)
		if err == nil {
			if setting := extractMarkedPipCertSetting(out); setting.Path != "" {
				return setting, nil
			}
		}
	}
	return pipCertSetting{}, nil
}
