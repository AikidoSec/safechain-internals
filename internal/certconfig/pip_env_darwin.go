//go:build darwin

package certconfig

import (
	"context"
	"os/exec"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

var pipCertShellLookups = []shellLookup{
	{"zsh", []string{"-lc", `if [ -n "${PIP_CERT:-}" ]; then printf 'AIKIDO_CERT=PIP_CERT:%s\n' "$PIP_CERT"; elif [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' "$REQUESTS_CA_BUNDLE"; elif [ -n "${SSL_CERT_FILE:-}" ]; then printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' "$SSL_CERT_FILE"; fi`}},
	{"zsh", []string{"-ic", `if [ -n "${PIP_CERT:-}" ]; then printf 'AIKIDO_CERT=PIP_CERT:%s\n' "$PIP_CERT"; elif [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' "$REQUESTS_CA_BUNDLE"; elif [ -n "${SSL_CERT_FILE:-}" ]; then printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' "$SSL_CERT_FILE"; fi`}},
	{"bash", []string{"-lc", `if [ -n "${PIP_CERT:-}" ]; then printf 'AIKIDO_CERT=PIP_CERT:%s\n' "$PIP_CERT"; elif [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' "$REQUESTS_CA_BUNDLE"; elif [ -n "${SSL_CERT_FILE:-}" ]; then printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' "$SSL_CERT_FILE"; fi`}},
	{"bash", []string{"-ic", `if [ -n "${PIP_CERT:-}" ]; then printf 'AIKIDO_CERT=PIP_CERT:%s\n' "$PIP_CERT"; elif [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' "$REQUESTS_CA_BUNDLE"; elif [ -n "${SSL_CERT_FILE:-}" ]; then printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' "$SSL_CERT_FILE"; fi`}},
	{"fish", []string{"--login", "-c", "if set -q PIP_CERT; printf 'AIKIDO_CERT=PIP_CERT:%s\n' $PIP_CERT; else if set -q REQUESTS_CA_BUNDLE; printf 'AIKIDO_CERT=REQUESTS_CA_BUNDLE:%s\n' $REQUESTS_CA_BUNDLE; else if set -q SSL_CERT_FILE; printf 'AIKIDO_CERT=SSL_CERT_FILE:%s\n' $SSL_CERT_FILE; end; end; end"}},
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
