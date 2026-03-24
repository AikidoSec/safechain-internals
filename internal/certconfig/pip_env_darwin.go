//go:build darwin

package certconfig

import (
	"context"
	"os/exec"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

var pipCertShellLookups = []shellLookup{
	{"zsh", []string{"-lc", `printf 'AIKIDO_CERT=%s\n' "${PIP_CERT:-${REQUESTS_CA_BUNDLE:-${SSL_CERT_FILE:-}}}"`}},
	{"zsh", []string{"-ic", `printf 'AIKIDO_CERT=%s\n' "${PIP_CERT:-${REQUESTS_CA_BUNDLE:-${SSL_CERT_FILE:-}}}"`}},
	{"bash", []string{"-lc", `printf 'AIKIDO_CERT=%s\n' "${PIP_CERT:-${REQUESTS_CA_BUNDLE:-${SSL_CERT_FILE:-}}}"`}},
	{"bash", []string{"-ic", `printf 'AIKIDO_CERT=%s\n' "${PIP_CERT:-${REQUESTS_CA_BUNDLE:-${SSL_CERT_FILE:-}}}"`}},
	{"fish", []string{"--login", "-c", "if set -q PIP_CERT; printf 'AIKIDO_CERT=%s\n' $PIP_CERT; else if set -q REQUESTS_CA_BUNDLE; printf 'AIKIDO_CERT=%s\n' $REQUESTS_CA_BUNDLE; else if set -q SSL_CERT_FILE; printf 'AIKIDO_CERT=%s\n' $SSL_CERT_FILE; end; end; end"}},
}

func runPipCertLookup(ctx context.Context) (string, error) {
	for _, lookup := range pipCertShellLookups {
		shellPath, err := exec.LookPath(lookup.name)
		if err != nil {
			continue
		}
		out, err := platform.RunAsCurrentUserWithPathEnv(ctx, shellPath, lookup.args...)
		if err == nil {
			if value := extractMarkedCertValue(out); value != "" {
				return value, nil
			}
		}
	}
	return "", nil
}
