package safechain

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/aikido/sc-agent/internal/platform"
	"github.com/aikido/sc-agent/internal/scanner"
)

type SafechainScanner struct{}

func New() scanner.Scanner {
	return &SafechainScanner{}
}

func (s *SafechainScanner) Name() string {
	return "safechain"
}

func (s *SafechainScanner) Install(ctx context.Context) error {
	cfg := platform.Get()
	binaryPath := filepath.Join(cfg.BinDir, "safe-chain")

	cmd := exec.CommandContext(ctx, binaryPath, "setup")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run safe-chain setup: %w", err)
	}

	return nil
}

func (s *SafechainScanner) Uninstall(ctx context.Context) error {
	cfg := platform.Get()
	binaryPath := filepath.Join(cfg.BinDir, "safe-chain")

	cmd := exec.CommandContext(ctx, binaryPath, "teardown")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run safe-chain teardown: %w", err)
	}

	return nil
}

func (s *SafechainScanner) IsInstalled(ctx context.Context) (bool, error) {
	return true, nil
}
