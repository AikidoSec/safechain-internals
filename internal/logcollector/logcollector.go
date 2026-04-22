package logcollector

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/config"
)

func Collect(ctx context.Context, config *config.ConfigInfo) error {
	if config.Token == "" {
		return fmt.Errorf("token is required to password-protect log archive")
	}

	logDir, err := prepareLogs(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare logs: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")

	zipPath, err := zipLogsWithPassword(ctx, logDir, timestamp, config.Token)
	if err != nil {
		return fmt.Errorf("failed to archive logs: %w", err)
	}
	log.Printf("Logs archived to %s", zipPath)

	if err := submitLogs(ctx, config, zipPath); err != nil {
		return fmt.Errorf("failed to submit logs: %w", err)
	}
	return nil
}
