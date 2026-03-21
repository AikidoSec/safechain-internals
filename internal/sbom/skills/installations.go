package skills

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

const lockFileName = "skills-lock.json"

type globalSkillsDir struct {
	variant string
	path    string
}

// globalSkillsDirs are the known user-level install directories used by agents
// supported by skills.sh. Each path is relative to the user's home directory.
var globalSkillsDirs = []globalSkillsDir{
	{variant: "codex", path: filepath.Join(".codex", "skills")},
	{variant: "claude", path: filepath.Join(".claude", "skills")},
	{variant: "cursor", path: filepath.Join(".cursor", "skills")},
	{variant: "windsurf", path: filepath.Join(".windsurf", "skills")},
	{variant: "gemini", path: filepath.Join(".gemini", "skills")},
	{variant: "kiro", path: filepath.Join(".kiro", "skills")},
	{variant: "opencode", path: filepath.Join(".opencode", "skills")},
}

func findInstallations(_ context.Context) ([]sbom.InstalledVersion, error) {
	homeDir := platform.GetConfig().HomeDir
	searchRoots := knownGlobalSkillsRoots(homeDir)

	lockFiles := findKnownLockFiles(searchRoots)
	sort.Slice(lockFiles, func(i, j int) bool {
		return lockFiles[i].path < lockFiles[j].path
	})

	var installations []sbom.InstalledVersion
	for _, lockFile := range lockFiles {
		log.Printf("Found %s for %s at: %s", lockFileName, lockFile.variant, lockFile.path)
		installations = append(installations, sbom.InstalledVersion{
			Ecosystem: "skills_sh",
			Variant:   lockFile.variant,
			Path:      lockFile.path,
			DataPath:  lockFile.path,
		})
	}
	return installations, nil
}

// knownGlobalSkillsRoots returns the list of global skills directories to check for installations.
func knownGlobalSkillsRoots(homeDir string) []globalSkillsDir {
	roots := make([]globalSkillsDir, 0, len(globalSkillsDirs))
	for _, dir := range globalSkillsDirs {
		roots = append(roots, globalSkillsDir{
			variant: dir.variant,
			path:    filepath.Join(homeDir, dir.path),
		})
	}
	return roots
}

// findKnownLockFiles checks the provided list of global skills directories for the presence of lock files.
func findKnownLockFiles(roots []globalSkillsDir) []globalSkillsDir {
	seen := make(map[string]bool)
	var found []globalSkillsDir
	for _, root := range roots {
		lockPath := filepath.Join(root.path, lockFileName)
		if _, err := os.Stat(lockPath); err == nil {
			resolved, err := filepath.EvalSymlinks(lockPath)
			if err != nil {
				resolved = lockPath
			}
			key := root.variant + "\x00" + strings.ToLower(resolved)
			if seen[key] {
				continue
			}
			seen[key] = true
			found = append(found, globalSkillsDir{
				variant: root.variant,
				path:    lockPath,
			})
		}
	}
	return found
}
