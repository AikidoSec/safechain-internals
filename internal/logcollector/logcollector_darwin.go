//go:build darwin

package logcollector

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

const networkExtensionLogPredicate = `subsystem == "com.aikido.endpoint.proxy.l4" ` +
	`OR process == "com.aikido.endpoint.proxy.l4.dev.extension" ` +
	`OR process == "Aikido Network Extension"`

func prepareLogs(ctx context.Context) (string, error) {
	logDir := platform.GetLogDir()

	timestamp := time.Now().UTC().Format("20060102-150405")
	if err := collectNetworkExtensionLogs(ctx, logDir, timestamp); err != nil {
		log.Printf("Failed to collect network extension logs: %v", err)
	}
	return logDir, nil
}

func collectNetworkExtensionLogs(ctx context.Context, logDir, timestamp string) error {
	outPath := filepath.Join(logDir, fmt.Sprintf("network_extension_%s.log", timestamp))

	output, err := utils.RunCommand(ctx, "log", "show",
		"--last", "30m",
		"--style", "compact",
		"--debug",
		"--info",
		"--predicate", networkExtensionLogPredicate,
	)
	if err != nil && output == "" {
		return fmt.Errorf("log show failed: %w", err)
	}

	if err := os.WriteFile(outPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write network extension logs: %w", err)
	}
	return nil
}

func cleanupPreparedLogs(logDir string) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		log.Printf("Failed to read %s for prepared-log cleanup: %v", logDir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "network_extension_") || !strings.HasSuffix(name, ".log") {
			continue
		}
		path := filepath.Join(logDir, name)
		if err := os.Remove(path); err != nil {
			log.Printf("Failed to remove %s: %v", path, err)
		}
	}
}
