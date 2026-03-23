package certconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type nodeTrustConfigurator interface {
	Install(context.Context) error
	Uninstall(context.Context) error
}

type nodeConfigurator struct {
	trust nodeTrustConfigurator
}

func newNodeConfigurator() Configurator {
	return &nodeConfigurator{
		trust: newNodeTrustConfigurator(combinedCaBundlePath()),
	}
}

func (c *nodeConfigurator) Name() string {
	return "node"
}

// originalNodeExtraCACertsPath is where we persist the user's pre-existing
// NODE_EXTRA_CA_CERTS value so it can be preserved across reinstalls and
// restored on uninstall.
func originalNodeExtraCACertsPath() string {
	return filepath.Join(platform.GetRunDir(), "endpoint-protection-node-original-extra-ca-certs.txt")
}

// ensureOriginalNodeExtraCACerts returns the user's pre-existing NODE_EXTRA_CA_CERTS
// value, saving it to disk on first install. On reinstall the saved value is
// returned directly — avoiding a live shell lookup that would return our own
// combined bundle path instead of the user's original.
func ensureOriginalNodeExtraCACerts(ctx context.Context) (string, error) {
	return ensureOriginalNodeExtraCACertsAt(ctx, originalNodeExtraCACertsPath(), runNodeExtraCACertsLookup)
}

func ensureOriginalNodeExtraCACertsAt(
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

func (c *nodeConfigurator) Install(ctx context.Context) error {
	original, err := ensureOriginalNodeExtraCACerts(ctx)
	if err != nil {
		return err
	}
	if _, err := ensureCombinedCABundle(original); err != nil {
		return err
	}
	return c.trust.Install(ctx)
}

func (c *nodeConfigurator) Uninstall(ctx context.Context) error {
	if err := c.trust.Uninstall(ctx); err != nil {
		return err
	}
	_ = os.Remove(originalNodeExtraCACertsPath())
	return removeCombinedCABundle()
}
