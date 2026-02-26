package sbom

import (
	"context"
	"fmt"
	"log"
)

type EcosystemEntry struct {
	Variant  string    `json:"variant"`
	Version  string    `json:"version"`
	Path     string    `json:"path"`
	Packages []Package `json:"packages"`
}

type SBOM struct {
	Entries []EcosystemEntry `json:"ecosystems"`
}

type Registry struct {
	managers map[string]PackageManager
}

func NewRegistry() *Registry {
	return &Registry{
		managers: make(map[string]PackageManager),
	}
}

func (r *Registry) Register(pm PackageManager) {
	r.managers[pm.Name()] = pm
}

func (r *Registry) Get(name string) (PackageManager, error) {
	pm, ok := r.managers[name]
	if !ok {
		return nil, fmt.Errorf("package manager '%s' not found", name)
	}
	return pm, nil
}

func (r *Registry) CollectAllPackages(ctx context.Context) SBOM {
	var entries []EcosystemEntry

	for name, pm := range r.managers {
		installations, err := pm.Installations(ctx)
		if err != nil {
			log.Printf("Failed to get installations for '%s': %v", name, err)
			continue
		}

		for _, inst := range installations {
			packages, err := pm.SBOM(ctx, inst)
			if err != nil {
				log.Printf("Failed to collect SBOM for '%s' (%s): %v", name, inst.Version, err)
				continue
			}
			variant := inst.Variant
			if variant == "" {
				variant = name
			}
			entries = append(entries, EcosystemEntry{
				Variant:  variant,
				Version:  inst.Version,
				Path:     inst.Path,
				Packages: packages,
			})
		}
	}

	return SBOM{Entries: entries}
}
