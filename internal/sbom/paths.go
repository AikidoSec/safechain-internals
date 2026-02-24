package sbom

import (
	"os"
	"path/filepath"
)

// DeduplicatePaths resolves symlinks for deduplication, filters out
// non-existent paths, and returns unique candidates in their original form.
func DeduplicatePaths(candidates []string) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, candidate := range candidates {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			resolved = candidate
		}
		if seen[resolved] {
			continue
		}
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		seen[resolved] = true
		paths = append(paths, candidate)
	}
	return paths
}
