package scannermanager

import (
	"context"
	"fmt"

	"github.com/aikido/safechain-agent/internal/scanner"
	"github.com/aikido/safechain-agent/internal/scanner/githook"
	"github.com/aikido/safechain-agent/internal/scanner/safechain"
	"github.com/aikido/safechain-agent/internal/scanner/vscode"
)

// Registry manages all available scanners
type Registry struct {
	scanners map[string]scanner.Scanner
}

// NewRegistry creates a new scanner registry with all available scanners
func NewRegistry() *Registry {
	registry := &Registry{
		scanners: make(map[string]scanner.Scanner),
	}

	// Register all scanners
	registry.Register(safechain.New())
	registry.Register(githook.New())
	registry.Register(vscode.New())

	return registry
}

// Register adds a scanner to the registry
func (r *Registry) Register(scanner scanner.Scanner) {
	r.scanners[scanner.Name()] = scanner
}

// Get retrieves a scanner by name
func (r *Registry) Get(name string) (scanner.Scanner, error) {
	s, ok := r.scanners[name]
	if !ok {
		return nil, fmt.Errorf("scanner '%s' not found", name)
	}
	return s, nil
}

// List returns all registered scanner names
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	return names
}

// InstallAll installs all registered scanners
func (r *Registry) InstallAll(ctx context.Context) error {
	for name, s := range r.scanners {
		if err := s.Install(ctx); err != nil {
			return fmt.Errorf("failed to install scanner '%s': %w", name, err)
		}
	}
	return nil
}

// UninstallAll uninstalls all registered scanners
func (r *Registry) UninstallAll(ctx context.Context) error {
	for name, s := range r.scanners {
		if err := s.Uninstall(ctx); err != nil {
			return fmt.Errorf("failed to uninstall scanner '%s': %w", name, err)
		}
	}
	return nil
}
