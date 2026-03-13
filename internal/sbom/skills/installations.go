package skills

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

const lockFileName = "skills-lock.json"

// globalSkillsDirs are the known user-level install directories used by agents
// supported by skills.sh. Each path is relative to the user's home directory.
var globalSkillsDirs = []string{
	filepath.Join(".codex", "skills"),
	filepath.Join(".claude", "skills"),
	filepath.Join(".cursor", "skills"),
	filepath.Join(".windsurf", "skills"),
	filepath.Join(".gemini", "skills"),
	filepath.Join(".kiro", "skills"),
	filepath.Join(".opencode", "skills"),
}

func findInstallations(_ context.Context) ([]sbom.InstalledVersion, error) {
	homeDir := platform.GetConfig().HomeDir
	searchRoots := knownGlobalSkillsRoots(homeDir)

	lockPaths := findKnownLockFiles(searchRoots)
	lockPaths = sbom.DeduplicatePaths(lockPaths)
	sort.Strings(lockPaths)

	var installations []sbom.InstalledVersion
	for _, lockPath := range lockPaths {
		log.Printf("Found %s at: %s", lockFileName, lockPath)
		installations = append(installations, sbom.InstalledVersion{
			Ecosystem: "skills_sh",
			Path:      lockPath,
			DataPath:  lockPath,
		})
	}
	return installations, nil
}

func knownGlobalSkillsRoots(homeDir string) []string {
	roots := make([]string, 0, len(globalSkillsDirs))
	for _, relativePath := range globalSkillsDirs {
		roots = append(roots, filepath.Join(homeDir, relativePath))
	}
	return roots
}

func findKnownLockFiles(roots []string) []string {
	var paths []string
	for _, root := range roots {
		lockPath := filepath.Join(root, lockFileName)
		if _, err := os.Stat(lockPath); err == nil {
			paths = append(paths, lockPath)
		}
	}
	return paths
}
