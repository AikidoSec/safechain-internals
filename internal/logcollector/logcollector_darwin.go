//go:build darwin

package logcollector

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/config"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

const logDir = "/Library/Logs/AikidoSecurity/EndpointProtection"

const networkExtensionLogPredicate = `subsystem == "com.aikido.endpoint.proxy.l4" ` +
	`OR process == "com.aikido.endpoint.proxy.l4.dist.extension" ` +
	`OR process == "Aikido Network Extension"`

func Collect(ctx context.Context, config *config.ConfigInfo) error {
	if config.Token == "" {
		return fmt.Errorf("token is required to password-protect log archive")
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to ensure log directory %s: %w", logDir, err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")

	if err := collectNetworkExtensionLogs(ctx, timestamp); err != nil {
		log.Printf("Failed to collect network extension logs: %v", err)
	}

	zipPath, err := zipLogsWithPassword(ctx, logDir, timestamp, config.Token)
	if err != nil {
		return fmt.Errorf("failed to archive logs: %w", err)
	}

	log.Printf("Logs archived to %s", zipPath)
	return nil
}

func collectNetworkExtensionLogs(ctx context.Context, timestamp string) error {
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
