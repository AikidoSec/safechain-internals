package npm

import (
	"context"
	"fmt"
	"log"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

func findInstallations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	paths, err := findBinaries()
	if err != nil {
		return nil, fmt.Errorf("failed to find npm binaries: %w", err)
	}
	var installations []sbom.InstalledVersion
	for _, path := range paths {
		version, err := getVersion(ctx, path)
		if err != nil {
			log.Printf("Skipping npm at %s: %v", path, err)
			continue
		}
		log.Printf("Found npm %s at: %s", version, path)
		installations = append(installations, sbom.InstalledVersion{
			Ecosystem: "npm",
			Version:   version,
			Path:      path,
		})
	}

	return installations, nil
}

func findBinaries() ([]string, error) {
	homeDir := platform.GetConfig().HomeDir
	return sbom.FindNodeBinaries(homeDir, binaryName()), nil
}
