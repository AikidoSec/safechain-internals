//go:build darwin

package certconfig

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type homebrewConfigurator struct{}

func newHomebrewConfigurator() Configurator { return &homebrewConfigurator{} }

func (c *homebrewConfigurator) Name() string { return "homebrew" }

func (c *homebrewConfigurator) Install(ctx context.Context) error {
	return syncHomebrewCACerts(ctx)
}

func (c *homebrewConfigurator) Uninstall(ctx context.Context) error {
	return syncHomebrewCACerts(ctx)
}

// syncHomebrewCACerts runs `brew postinstall ca-certificates`, which merges the
// macOS system keychain into Homebrew's shared OpenSSL CA bundle at
// /opt/homebrew/etc/ca-certificates/. This covers all Homebrew-installed tools
// that link against Homebrew's OpenSSL (Ruby, curl, git, Claude CLI, etc.).
//
// The command is a no-op if Homebrew or the ca-certificates package is not
// installed — both cases are logged and treated as non-fatal.
func syncHomebrewCACerts(ctx context.Context) error {
	brewPath, err := exec.LookPath("brew")
	if err != nil {
		log.Printf("homebrew: brew not found, skipping ca-certificates sync")
		return nil
	}

	out, err := platform.RunAsCurrentUserWithPathEnv(ctx, brewPath, "postinstall", "ca-certificates")
	if err != nil {
		return fmt.Errorf("brew postinstall ca-certificates: %w (output: %s)", err, out)
	}
	return nil
}
