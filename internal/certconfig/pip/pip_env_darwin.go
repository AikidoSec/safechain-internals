//go:build darwin

package pip

import (
	"context"
	"os/exec"

	"github.com/AikidoSec/safechain-internals/internal/certconfig/shared"
	"github.com/AikidoSec/safechain-internals/internal/platform"
)

// certShellLookups tries login and interactive startup files separately
// because they are sourced in different modes:
//   - Login non-interactive (-lc): ~/.zprofile or ~/.bash_profile
//   - Interactive non-login (-ic): ~/.zshrc or ~/.bashrc
//   - fish --login: ~/.config/fish/config.fish
//
// Each command wraps the result in a unique marker so shell startup noise does
// not contaminate the discovered Python CA bundle override.
var certShellLookups = []shared.ShellLookup{
	{Name: "zsh", Args: []string{"-lc", `if [ -n "${PIP_CERT:-}" ]; then printf 'AIKIDO_CERT=PIP_CERT:%s\n' "$PIP_CERT"; elif [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' "$REQUESTS_CA_BUNDLE"; elif [ -n "${SSL_CERT_FILE:-}" ]; then printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' "$SSL_CERT_FILE"; fi`}},
	{Name: "zsh", Args: []string{"-ic", `if [ -n "${PIP_CERT:-}" ]; then printf 'AIKIDO_CERT=PIP_CERT:%s\n' "$PIP_CERT"; elif [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' "$REQUESTS_CA_BUNDLE"; elif [ -n "${SSL_CERT_FILE:-}" ]; then printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' "$SSL_CERT_FILE"; fi`}},
	{Name: "bash", Args: []string{"-lc", `if [ -n "${PIP_CERT:-}" ]; then printf 'AIKIDO_CERT=PIP_CERT:%s\n' "$PIP_CERT"; elif [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' "$REQUESTS_CA_BUNDLE"; elif [ -n "${SSL_CERT_FILE:-}" ]; then printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' "$SSL_CERT_FILE"; fi`}},
	{Name: "bash", Args: []string{"-ic", `if [ -n "${PIP_CERT:-}" ]; then printf 'AIKIDO_CERT=PIP_CERT:%s\n' "$PIP_CERT"; elif [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' "$REQUESTS_CA_BUNDLE"; elif [ -n "${SSL_CERT_FILE:-}" ]; then printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' "$SSL_CERT_FILE"; fi`}},
	{Name: "fish", Args: []string{"--login", "-c", "if set -q PIP_CERT; printf 'AIKIDO_CERT=PIP_CERT:%s\n' $PIP_CERT; else if set -q REQUESTS_CA_BUNDLE; printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' $REQUESTS_CA_BUNDLE; else if set -q SSL_CERT_FILE; printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' $SSL_CERT_FILE; end; end; end"}},
}

func runCertLookup(ctx context.Context) (CertSetting, error) {
	for _, lookup := range certShellLookups {
		shellPath, err := exec.LookPath(lookup.Name)
		if err != nil {
			continue
		}
		out, err := platform.RunAsCurrentUserWithPathEnv(ctx, shellPath, lookup.Args...)
		if err == nil {
			if setting := extractMarkedCertSetting(out); setting.Path != "" {
				return setting, nil
			}
		}
	}
	return CertSetting{}, nil
}
