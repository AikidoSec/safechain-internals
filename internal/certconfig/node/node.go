package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/certconfig/shared"
	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type trustConfigurator interface {
	Install(context.Context) error
	Uninstall(context.Context) error
}

type Configurator struct {
	trust trustConfigurator
}

func New() *Configurator {
	return &Configurator{
		trust: newTrustConfigurator(shared.CombinedCaBundlePath()),
	}
}

func (c *Configurator) Name() string {
	return "node"
}

// originalExtraCACertsPath is where we persist the user's pre-existing
// NODE_EXTRA_CA_CERTS value so it can be preserved across reinstalls and
// restored on uninstall.
func originalExtraCACertsPath() string {
	return filepath.Join(platform.GetRunDir(), "endpoint-protection-node-original-extra-ca-certs.txt")
}

// ensureOriginalExtraCACerts returns the user's pre-existing NODE_EXTRA_CA_CERTS
// value, saving it to disk on first install. On reinstall the saved value is
// returned directly — avoiding a live shell lookup that would return our own
// combined bundle path instead of the user's original.
func ensureOriginalExtraCACerts(ctx context.Context) (string, error) {
	return ensureOriginalExtraCACertsAt(ctx, originalExtraCACertsPath(), runExtraCACertsLookup)
}

func ensureOriginalExtraCACertsAt(
	ctx context.Context,
	savedPath string,
	lookup func(context.Context) (string, error),
) (string, error) {
	if data, err := os.ReadFile(savedPath); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	original, err := lookup(ctx)
	if err != nil {
		return "", fmt.Errorf("read existing NODE_EXTRA_CA_CERTS: %w", err)
	}
	original = strings.TrimSpace(original)

	if err := os.WriteFile(savedPath, []byte(original), 0o600); err != nil {
		return "", fmt.Errorf("persist existing NODE_EXTRA_CA_CERTS: %w", err)
	}
	return original, nil
}

func (c *Configurator) Install(ctx context.Context) error {
	original, err := ensureOriginalExtraCACerts(ctx)
	if err != nil {
		return err
	}
	if _, err := shared.EnsureCombinedCABundle(original); err != nil {
		return err
	}
	return c.trust.Install(ctx)
}

func (c *Configurator) Uninstall(ctx context.Context) error {
	if err := c.trust.Uninstall(ctx); err != nil {
		return err
	}
	_ = os.Remove(originalExtraCACertsPath())
	return shared.RemoveCombinedCABundle()
}
