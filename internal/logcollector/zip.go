package logcollector

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

func zipLogs(ctx context.Context, dir, timestamp string) (string, error) {
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
	zipPath := filepath.Join(dir, zipName)

	out, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %w", err)
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	defer zw.Close()

	for _, name := range files {
		if err := ctx.Err(); err != nil {
			os.Remove(zipPath)
			return "", err
		}
		if err := addFile(zw, filepath.Join(dir, name), name); err != nil {
			os.Remove(zipPath)
			return "", fmt.Errorf("failed to add %s to zip: %w", name, err)
		}
	}

	return zipPath, nil
}

func addFile(zw *zip.Writer, srcPath, entryName string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	info, err := src.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = entryName
	header.Method = zip.Deflate

	w, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, src); err != nil {
		return err
	}
	return nil
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
