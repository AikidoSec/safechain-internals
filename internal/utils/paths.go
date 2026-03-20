package utils

import (
	"path/filepath"
	"strings"
)

func ExpandHomePath(path string, homeDir string) string {
	if path == "" {
		return path
	}
	if path == "~" {
		return homeDir
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		return filepath.Join(homeDir, path[2:])
	}
	return path
}
