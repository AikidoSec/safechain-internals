package skills

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

type skillsEntry struct {
	Name   string   `json:"name"`
	Path   string   `json:"path"`
	Scope  string   `json:"scope"`
	Agents []string `json:"agents"`
}

func findInstallations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	homeDir := platform.GetConfig().HomeDir
	binaries := findBinaries(homeDir)

	for _, binary := range binaries {
		entries, err := listGlobalSkills(ctx, binary)
		if err != nil {
			log.Printf("Skipping skills at %s: %v", binary, err)
			continue
		}
		if len(entries) == 0 {
			continue
		}
		skillsDir := skillsDirFromEntries(entries, homeDir)
		log.Printf("Found %d global skills at: %s", len(entries), skillsDir)
		return []sbom.InstalledVersion{{
			Ecosystem: "skills_sh",
			Path:      skillsDir,
			DataPath:  binary,
		}}, nil
	}
	return nil, nil
}

// skillsDirFromEntries derives the global skills root directory from CLI output.
// The CLI reports individual skill paths like ~/.agents/skills/<name>, so the
// parent of the first entry's path is the skills directory.
// Falls back to the conventional ~/.agents/skills if no entries have a path.
func skillsDirFromEntries(entries []skillsEntry, homeDir string) string {
	for _, e := range entries {
		if e.Path != "" {
			return filepath.Dir(e.Path)
		}
	}
	return filepath.Join(homeDir, ".agents", "skills")
}

func listGlobalSkills(ctx context.Context, binary string) ([]skillsEntry, error) {
	args := []string{"ls", "-g", "--json"}
	if strings.HasPrefix(filepath.Base(binary), "npx") {
		// Invoked via npx: prepend --prefer-offline and the package name.
		args = append([]string{"--prefer-offline", "skills"}, args...)
	}
	output, err := runSkills(ctx, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("skills ls -g --json: %w", err)
	}
	return parseSkillsLsOutput(output)
}

func parseSkillsLsOutput(output string) ([]skillsEntry, error) {
	trimmedOutput := strings.TrimSpace(output)
	if trimmedOutput == "" {
		return nil, nil
	}
	var entries []skillsEntry
	if err := json.Unmarshal([]byte(trimmedOutput), &entries); err != nil {
		return nil, fmt.Errorf("failed to parse skills ls output: %w", err)
	}
	return entries, nil
}
