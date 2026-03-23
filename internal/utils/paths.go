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
	if strings.HasPrefix(path, "${HOME}") {
		return homeDir + path[7:]
	}
	if strings.HasPrefix(path, "$HOME/") || strings.HasPrefix(path, "$HOME\\") || path == "$HOME" {
		return homeDir + path[5:]
	}
	return path
}
