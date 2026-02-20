package sbom

import (
	"context"
	"fmt"
	"log"
)

type Registry struct {
	managers map[string]PackageManager
}

func NewRegistry() *Registry {
	registry := &Registry{
		managers: make(map[string]PackageManager),
	}

	registry.Register(NewNpmPackageManager())
	registry.Register(NewVSCodeExtensionsManager())
	return registry
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

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.managers))
	for name := range r.managers {
		names = append(names, name)
	}
	return names
}

func (r *Registry) CollectAllPackages(ctx context.Context) map[string][]Package {
	result := make(map[string][]Package)

	for name, pm := range r.managers {
		installations, err := pm.Installations(ctx)
		if err != nil {
			log.Printf("Failed to get installations for '%s': %v", name, err)
			continue
		}

		for _, inst := range installations {
			key := fmt.Sprintf("%s@%s", name, inst.Version)
			packages, err := pm.SBOM(ctx, inst)
			if err != nil {
				log.Printf("Failed to collect SBOM for '%s' (%s): %v", name, inst.Version, err)
				continue
			}
			result[key] = packages
		}
	}

	return result
}
