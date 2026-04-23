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
		return fmt.Errorf("token is required to submit log archive")
	}

	logDir, err := prepareLogs(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare logs: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")

	zipPath, err := zipLogs(ctx, logDir, timestamp)
	if err != nil {
		return fmt.Errorf("failed to archive logs: %w", err)
	}
	log.Printf("Logs archived to %s", zipPath)

	err = submitLogs(ctx, config, zipPath)
	if err != nil {
		log.Printf("failed to submit logs: %v", err)
	}

	cleanupPreparedLogs(logDir)
	cleanupZips(logDir)
	return err
}
