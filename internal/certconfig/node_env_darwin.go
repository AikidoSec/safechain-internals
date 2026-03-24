//go:build darwin

package certconfig

import (
	"context"
	"os/exec"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

// shellLookup describes how to query NODE_EXTRA_CA_CERTS from a specific shell.
type shellLookup struct {
	name string
	args []string
}

// nodeCACertsShellLookups tries login and interactive startup files separately
// because they are sourced in different modes:
//   - Login non-interactive (-lc): ~/.zshenv, ~/.zprofile (zsh) or ~/.bash_profile (bash)
//   - Interactive non-login (-ic): ~/.zshrc (zsh) or ~/.bashrc (bash)
//   - fish --login: ~/.config/fish/config.fish
//
// Each command wraps the value in a unique marker so interactive startup noise
// (prompts, oh-my-zsh banners, etc.) does not contaminate the result.
var nodeCACertsShellLookups = []shellLookup{
	{"zsh", []string{"-lc", `printf 'AIKIDO_CERT=%s\n' "${NODE_EXTRA_CA_CERTS:-}"`}},
	{"zsh", []string{"-ic", `printf 'AIKIDO_CERT=%s\n' "${NODE_EXTRA_CA_CERTS:-}"`}},
	{"bash", []string{"-lc", `printf 'AIKIDO_CERT=%s\n' "${NODE_EXTRA_CA_CERTS:-}"`}},
	{"bash", []string{"-ic", `printf 'AIKIDO_CERT=%s\n' "${NODE_EXTRA_CA_CERTS:-}"`}},
	// set -q guards against fish 3.x warnings on unset variable access.
	{"fish", []string{"--login", "-c", "set -q NODE_EXTRA_CA_CERTS; and printf 'AIKIDO_CERT=%s\n' $NODE_EXTRA_CA_CERTS"}},
}

const aikidoCertMarker = "AIKIDO_CERT="

func runNodeExtraCACertsLookup(ctx context.Context) (string, error) {
	for _, lookup := range nodeCACertsShellLookups {
		shellPath, err := exec.LookPath(lookup.name)
		if err != nil {
			continue // shell not installed
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
