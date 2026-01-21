package scannermanager

import (
	"context"
	"fmt"
	"log"

	"github.com/AikidoSec/safechain-internals/internal/scanner"
	"github.com/AikidoSec/safechain-internals/internal/scanner/safechain"
)

type Registry struct {
	scanners map[string]scanner.Scanner
}

func NewRegistry() *Registry {
	registry := &Registry{
		scanners: make(map[string]scanner.Scanner),
	}

	registry.Register(safechain.New())
	return registry
}

func (r *Registry) Register(scanner scanner.Scanner) {
	r.scanners[scanner.Name()] = scanner
}

func (r *Registry) Get(name string) (scanner.Scanner, error) {
	s, ok := r.scanners[name]
	if !ok {
		return nil, fmt.Errorf("scanner '%s' not found", name)
	}
	return s, nil
}

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.scanners))
	for name := range r.scanners {
		names = append(names, name)
	}
	return names
}

func (r *Registry) InstallAll(ctx context.Context) error {
	for name, s := range r.scanners {
		if !s.IsInstalled(ctx) {
			log.Printf("Installing scanner '%s'...", name)
			if err := s.Install(ctx); err != nil {
				log.Printf("Failed to install scanner '%s': %v", name, err)
				continue
			}
			log.Printf("Scanner '%s' installed successfully!", name)
		}
	}
	return nil
}

func (r *Registry) UninstallAll(ctx context.Context) error {
	for name, s := range r.scanners {
		if s.IsInstalled(ctx) {
			log.Printf("Uninstalling scanner '%s'...", name)
			if err := s.Uninstall(ctx); err != nil {
				log.Printf("Failed to uninstall scanner '%s': %v", name, err)
				continue
			}
			log.Printf("Scanner '%s' uninstalled successfully!", name)
		}
	}
	return nil
}
