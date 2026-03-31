//go:build darwin

package node

import (
	"context"
	"os/exec"

	"github.com/AikidoSec/safechain-internals/internal/certconfig/shared"
	"github.com/AikidoSec/safechain-internals/internal/platform"
)

// extraCACertsShellLookups tries login and interactive startup files separately
// because they are sourced in different modes:
//   - Login non-interactive (-lc): ~/.zshenv, ~/.zprofile (zsh) or ~/.bash_profile (bash)
//   - Interactive non-login (-ic): ~/.zshrc (zsh) or ~/.bashrc (bash)
//   - fish --login: ~/.config/fish/config.fish
//
// Each command wraps the value in a unique marker so interactive startup noise
// (prompts, oh-my-zsh banners, etc.) does not contaminate the result.
var extraCACertsShellLookups = []shared.ShellLookup{
	{Name: "zsh", Args: []string{"-lc", `printf 'AIKIDO_CERT=%s\n' "${NODE_EXTRA_CA_CERTS:-}"`}},
	{Name: "zsh", Args: []string{"-ic", `printf 'AIKIDO_CERT=%s\n' "${NODE_EXTRA_CA_CERTS:-}"`}},
	{Name: "bash", Args: []string{"-lc", `printf 'AIKIDO_CERT=%s\n' "${NODE_EXTRA_CA_CERTS:-}"`}},
	{Name: "bash", Args: []string{"-ic", `printf 'AIKIDO_CERT=%s\n' "${NODE_EXTRA_CA_CERTS:-}"`}},
	// set -q guards against fish 3.x warnings on unset variable access.
	{Name: "fish", Args: []string{"--login", "-c", "set -q NODE_EXTRA_CA_CERTS; and printf 'AIKIDO_CERT=%s\n' $NODE_EXTRA_CA_CERTS"}},
}

func runExtraCACertsLookup(ctx context.Context) (string, error) {
	for _, lookup := range extraCACertsShellLookups {
		shellPath, err := exec.LookPath(lookup.Name)
		if err != nil {
			continue // shell not installed
		}
		out, err := platform.RunAsCurrentUserWithPathEnv(ctx, shellPath, lookup.Args...)
		if err == nil {
			if value := shared.ExtractMarkedCertValue(out); value != "" {
				return value, nil
			}
		}
	}
	return "", nil
}
