//go:build darwin

package certconfig

import (
	"context"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

// shellLookup describes how to query NODE_EXTRA_CA_CERTS from a specific shell.
type shellLookup struct {
	name string
	args []string
}

var nodeCACertsShellLookups = []shellLookup{
	// zsh is the macOS default since Catalina; -l sources ~/.zshenv and ~/.zprofile.
	{"zsh", []string{"-lc", `printf %s "${NODE_EXTRA_CA_CERTS:-}"`}},
	// bash covers older setups using ~/.bash_profile.
	{"bash", []string{"-lc", `printf %s "${NODE_EXTRA_CA_CERTS:-}"`}},
	// fish users who set NODE_EXTRA_CA_CERTS only in config.fish won't have it
	// visible to zsh/bash; --login sources ~/.config/fish/config.fish.
	// `set -q` guards against fish 3.x warnings on unset variable access.
	{"fish", []string{"--login", "-c", "set -q NODE_EXTRA_CA_CERTS; and printf '%s' $NODE_EXTRA_CA_CERTS"}},
}

func runNodeExtraCACertsLookup(ctx context.Context) (string, error) {
	for _, lookup := range nodeCACertsShellLookups {
		out, err := platform.RunAsCurrentUser(ctx, lookup.name, lookup.args)
		if err == nil && strings.TrimSpace(out) != "" {
			return out, nil
		}
	}
	return "", nil
}
