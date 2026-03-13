package skills

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

type lockFile struct {
	Version int                    `json:"version"`
	Skills  map[string]skillEntry  `json:"skills"`
}

type skillEntry struct {
	Source       string `json:"source"`
	SourceType   string `json:"sourceType"`
	ComputedHash string `json:"computedHash"`
}

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

func (s *SkillsSh) SBOM(_ context.Context, installation sbom.InstalledVersion) ([]sbom.Package, error) {
	data, err := os.ReadFile(installation.DataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", installation.DataPath, err)
	}

	var lock lockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", installation.DataPath, err)
	}

	var packages []sbom.Package
	for skillName, entry := range lock.Skills {
		if entry.Source == "" || skillName == "" {
			continue
		}
		packages = append(packages, sbom.Package{
			Id:      entry.Source + "/" + skillName,
			Name:    skillName,
			Version: entry.ComputedHash,
		})
	}

	return packages, nil
}
