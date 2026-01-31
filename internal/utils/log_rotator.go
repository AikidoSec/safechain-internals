package utils

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	RotationLoopInterval = 1 * time.Hour
)

type logFile struct {
	path    string
	maxSize int64
}

type LogRotator struct {
	mu       sync.RWMutex
	logFiles []logFile
}

func NewLogRotator() *LogRotator {
	return &LogRotator{
		logFiles: make([]logFile, 0),
	}
}

func (r *LogRotator) AddLogFile(path string, maxSize int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logFiles = append(r.logFiles, logFile{path: path, maxSize: maxSize})
}

func (r *LogRotator) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go r.rotationLoop(ctx, wg)
}

func (r *LogRotator) rotationLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(RotationLoopInterval)
	defer ticker.Stop()

	r.checkAndRotate()

	for {
		select {
		case <-ticker.C:
			r.checkAndRotate()
		case <-ctx.Done():
			return
		}
	}
}

func (r *LogRotator) checkAndRotate() {
	r.mu.RLock()
	files := make([]logFile, len(r.logFiles))
	copy(files, r.logFiles)
	r.mu.RUnlock()

	for _, lf := range files {
		r.rotateIfNeeded(lf)
	}
}

func (r *LogRotator) rotateIfNeeded(lf logFile) {
	info, err := os.Stat(lf.path)
	if err != nil {
		log.Printf("Failed to stat log file: %s", lf.path)
		return
	}

	if info.Size() <= lf.maxSize {
		return
	}

	timestamp := time.Now().UTC().Format("2006-01-02-15")
	dir, base := filepath.Dir(lf.path), filepath.Base(lf.path)
	ext := filepath.Ext(base)
	nameWithoutExt := base[:len(base)-len(ext)]
	newPath := filepath.Join(dir, nameWithoutExt+"."+timestamp+ext)

	if err := os.Rename(lf.path, newPath); err != nil {
		log.Printf("Failed to rotate log file: %s -> %s", lf.path, newPath)
		return
	}

	log.Printf("Rotated log file: %s -> %s", lf.path, newPath)
}
