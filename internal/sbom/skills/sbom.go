package skills

import (
	"context"
	"fmt"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

type SkillsSh struct{}

func New() sbom.PackageManager {
	return &SkillsSh{}
}

func (s *SkillsSh) Name() string {
	return "skills_sh"
}

func (s *SkillsSh) Installations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	return findInstallations(ctx)
}

func (s *SkillsSh) SBOM(ctx context.Context, installation sbom.InstalledVersion) ([]sbom.Package, error) {
	entries, err := listGlobalSkills(ctx, installation.DataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list global skills: %w", err)
	}
	return packagesFromEntries(entries), nil
}

func packagesFromEntries(entries []skillsEntry) []sbom.Package {
	packages := make([]sbom.Package, 0, len(entries))
	for _, entry := range entries {
		packages = append(packages, sbom.Package{
			Id:   entry.Name,
			Name: entry.Name,
		})
	}
	return packages
}
