package logcollector

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func zipLogsWithPassword(ctx context.Context, dir, timestamp, password string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("failed to read log directory: %w", err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) == ".zip" {
			continue
		}
		files = append(files, name)
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no logs to archive in %s", dir)
	}

	zipName := fmt.Sprintf("aikido-endpoint-protection-logs-%s.zip", timestamp)
	args := []string{"-j", "-P", password, zipName}
	args = append(args, files...)

	cmd := exec.CommandContext(ctx, "zip", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("zip command failed: %w (output: %s)", err, string(out))
	}

	return filepath.Join(dir, zipName), nil
}

func cleanupZips(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("Failed to read %s for zip cleanup: %v", dir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".zip" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := os.Remove(path); err != nil {
			log.Printf("Failed to remove %s: %v", path, err)
		}
	}
}
