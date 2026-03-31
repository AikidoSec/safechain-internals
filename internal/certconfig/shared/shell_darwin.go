//go:build darwin

package shared

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/utils"
)

// ShellLookup describes how to query an environment variable from a specific shell.
type ShellLookup struct {
	Name string
	Args []string
}

// DarwinShellTarget represents a shell startup file to inject a managed block into.
type DarwinShellTarget struct {
	Path            string
	Body            string
	CreateIfMissing bool
}

// InstallDarwinShellTargets writes managed blocks to the given shell targets.
func InstallDarwinShellTargets(targets []DarwinShellTarget, format ManagedBlockFormat) error {
	for _, target := range targets {
		if _, err := os.Stat(target.Path); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to stat %s: %w", target.Path, err)
			}
			if !target.CreateIfMissing {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target.Path), 0o755); err != nil {
				return fmt.Errorf("failed to create config dir for %s: %w", target.Path, err)
			}
		}
		if err := WriteManagedBlock(target.Path, target.Body, 0o644, format); err != nil {
			return err
		}
	}
	return nil
}

// UninstallDarwinShellTargets removes managed blocks from the given shell targets.
func UninstallDarwinShellTargets(targets []DarwinShellTarget, format ManagedBlockFormat) error {
	for _, target := range targets {
		if err := utils.RemoveManagedBlock(target.Path, 0o644, format.StartMarker, format.EndMarker); err != nil {
			return err
		}
	}
	return nil
}
