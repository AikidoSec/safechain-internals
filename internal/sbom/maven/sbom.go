package maven

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

const name = "maven"

type Maven struct{}

func New() sbom.PackageManager {
	return &Maven{}
}

func (m *Maven) Name() string {
	return name
}

func (m *Maven) Installations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	paths, err := findBinaries()
	if err != nil {
		return nil, fmt.Errorf("failed to find maven binaries: %w", err)
	}
	log.Printf("Found %d maven binaries: %v", len(paths), paths)

	repoPath := defaultRepositoryPath()

	var installations []sbom.InstalledVersion
	for _, path := range paths {
		version, err := getVersion(ctx, path)
		if err != nil {
			log.Printf("Skipping maven at %s: %v", path, err)
			continue
		}
		log.Printf("Found maven %s at: %s", version, path)
		installations = append(installations, sbom.InstalledVersion{
			Version:  version,
			Path:     path,
			DataPath: repoPath,
		})
	}

	return installations, nil
}

func (m *Maven) SBOM(_ context.Context, installation sbom.InstalledVersion) ([]sbom.Package, error) {
	repoDir := installation.DataPath
	if repoDir == "" {
		repoDir = defaultRepositoryPath()
	}

	if _, err := os.Stat(repoDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to access maven repository: %w", err)
	}

	return scanRepository(repoDir)
}

func defaultRepositoryPath() string {
	return filepath.Join(platform.GetConfig().HomeDir, ".m2", "repository")
}

// scanRepository walks the local Maven repository and extracts package
// coordinates from the standard directory layout:
//
//	<repo>/<groupId-as-path>/<artifactId>/<version>/<artifactId>-<version>.pom
func scanRepository(repoDir string) ([]sbom.Package, error) {
	var packages []sbom.Package

	err := filepath.WalkDir(repoDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".pom") {
			return nil
		}

		pkg, err := parsePackageFromPomPath(repoDir, path)
		if err != nil {
			return nil
		}
		packages = append(packages, *pkg)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk maven repository: %w", err)
	}

	return packages, nil
}

// parsePackageFromPomPath derives Maven coordinates from the filesystem path.
// Expected layout: <repoDir>/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom
func parsePackageFromPomPath(repoDir, pomPath string) (*sbom.Package, error) {
	rel, err := filepath.Rel(repoDir, pomPath)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	// Minimum: groupId(1+) / artifactId / version / filename = 4 parts
	if len(parts) < 4 {
		return nil, fmt.Errorf("path too short: %s", rel)
	}

	filename := parts[len(parts)-1]
	version := parts[len(parts)-2]
	artifactId := parts[len(parts)-3]
	groupParts := parts[:len(parts)-3]
	groupId := strings.Join(groupParts, ".")

	expectedFilename := artifactId + "-" + version + ".pom"
	if filename != expectedFilename {
		return nil, fmt.Errorf("unexpected pom filename: %s", filename)
	}

	return &sbom.Package{
		Name:    groupId + ":" + artifactId,
		Version: version,
	}, nil
}
