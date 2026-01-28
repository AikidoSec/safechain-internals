package utils

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	ReapLoopInterval = 1 * time.Hour
)

type reapableLog struct {
	path      string
	maxLogAge time.Duration
}

type LogReaper struct {
	mu       sync.RWMutex
	logFiles []reapableLog
}

func NewLogReaper() *LogReaper {
	return &LogReaper{
		logFiles: make([]reapableLog, 0),
	}
}

func (r *LogReaper) AddLogFile(path string, maxLogAgeHours int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logFiles = append(r.logFiles, reapableLog{path: path, maxLogAge: time.Duration(maxLogAgeHours) * time.Hour})
}

func (r *LogReaper) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go r.reapLoop(ctx, wg)
}

func (r *LogReaper) reapLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(ReapLoopInterval)
	defer ticker.Stop()

	r.checkAndReap()

	for {
		select {
		case <-ticker.C:
			r.checkAndReap()
		case <-ctx.Done():
			return
		}
	}
}

func (r *LogReaper) checkAndReap() {
	r.mu.RLock()
	files := make([]reapableLog, len(r.logFiles))
	copy(files, r.logFiles)
	r.mu.RUnlock()

	for _, lf := range files {
		r.reapOldLogs(lf)
	}
}

func (r *LogReaper) reapOldLogs(lf reapableLog) {
	dir := filepath.Dir(lf.path)
	baseName := filepath.Base(lf.path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("Failed to read log directory: %s", dir)
		return
	}

	now := time.Now().UTC()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, baseName+".") {
			continue
		}

		timestampStr := strings.TrimPrefix(name, baseName+".")
		logTime, err := time.Parse("2006-01-02-15", timestampStr)
		if err != nil {
			log.Printf("Failed to parse log file timestamp: %s", timestampStr)
			continue
		}

		if now.Sub(logTime) > lf.maxLogAge {
			os.Remove(filepath.Join(dir, name))
			log.Printf("Reaped old log file: %s", filepath.Join(dir, name))
		}
	}
}
