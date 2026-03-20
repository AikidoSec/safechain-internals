//go:build darwin

package certconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type darwinNodeTrustConfigurator struct {
	body string
}

func newNodeTrustConfigurator(bundlePath string) nodeTrustConfigurator {
	return &darwinNodeTrustConfigurator{
		body: strings.Join([]string{
			"# Allow Node.js tooling to trust the SafeChain MITM CA while preserving public roots.",
			shellExportLine("NODE_EXTRA_CA_CERTS", bundlePath),
		}, "\n"),
	}
}

func (c *darwinNodeTrustConfigurator) Install(_ context.Context) error {
	for _, path := range shellProfilePaths() {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		if err := writeManagedBlock(path, c.body, 0o644, shellManagedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

func (c *darwinNodeTrustConfigurator) Uninstall(_ context.Context) error {
	for _, path := range shellProfilePaths() {
		if err := removeManagedBlock(path, 0o644, shellManagedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

var shellManagedBlockFormat = managedBlockFormat{
	startMarker: "# aikido-cert-config-start",
	endMarker:   "# aikido-cert-config-end",
}

func shellProfilePaths() []string {
	homeDir := platform.GetConfig().HomeDir
	return []string{
		filepath.Join(homeDir, ".zshrc"),
		filepath.Join(homeDir, ".zprofile"),
		filepath.Join(homeDir, ".bash_profile"),
		filepath.Join(homeDir, ".bashrc"),
		filepath.Join(homeDir, ".profile"),
	}
}

func shellExportLine(name string, value string) string {
	return fmt.Sprintf("export %s=%q", name, value)
}
