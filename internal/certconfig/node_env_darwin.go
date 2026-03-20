//go:build darwin

package certconfig

import (
	"context"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func runNodeExtraCACertsLookup(ctx context.Context) (string, error) {
	// Try the user's likely shells in order. zsh is the macOS default since Catalina
	// and sources ~/.zshrc; bash covers older setups using ~/.bash_profile.
	for _, shell := range []string{"zsh", "bash"} {
		out, err := platform.RunAsCurrentUser(ctx, shell, []string{
			"-lc",
			`printf %s "${NODE_EXTRA_CA_CERTS:-}"`,
		})
		if err == nil && strings.TrimSpace(out) != "" {
			return out, nil
		}
	}
	return "", nil
}
