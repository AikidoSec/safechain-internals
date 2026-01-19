package safechain

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-agent/internal/platform"
	"github.com/AikidoSec/safechain-agent/internal/scanner"
	"github.com/AikidoSec/safechain-agent/internal/utils"
)

const (
	repoURL = "https://github.com/AikidoSec/safe-chain"
)

type SafechainScanner struct {
}

func New() scanner.Scanner {
	return &SafechainScanner{}
}

func (s *SafechainScanner) Name() string {
	return "safechain"
}

func (s *SafechainScanner) Install(ctx context.Context) error {
	log.Printf("Installing safe-chain via install script...")

	scriptURL := repoURL + "/releases/latest/download/install-safe-chain.sh"
	scriptPath := filepath.Join(os.TempDir(), "install-safe-chain.sh")

	log.Printf("Downloading install script from %s...", scriptURL)
	if err := utils.DownloadBinary(ctx, scriptURL, scriptPath); err != nil {
		return fmt.Errorf("failed to download install script: %w", err)
	}
	defer os.Remove(scriptPath)

	if err := platform.RunAsCurrentUser(ctx, "sh", []string{scriptPath}); err != nil {
		return fmt.Errorf("failed to run install script: %w", err)
	}

	return nil
}

func (s *SafechainScanner) Uninstall(ctx context.Context) error {
	log.Printf("Uninstalling safe-chain via uninstall script...")

	scriptURL := repoURL + "/releases/latest/download/uninstall-safe-chain.sh"
	scriptPath := filepath.Join(os.TempDir(), "uninstall-safe-chain.sh")

	log.Printf("Downloading uninstall script from %s...", scriptURL)
	if err := utils.DownloadBinary(ctx, scriptURL, scriptPath); err != nil {
		return fmt.Errorf("failed to download uninstall script: %w", err)
	}
	defer os.Remove(scriptPath)

	if err := platform.RunAsCurrentUser(ctx, "sh", []string{scriptPath}); err != nil {
		return fmt.Errorf("failed to run uninstall script: %w", err)
	}

	return nil
}

func (s *SafechainScanner) IsInstalled(ctx context.Context) (bool, error) {
	cfg := platform.GetConfig()
	_, err := os.Stat(cfg.SafeChainBinaryPath)
	return err == nil, nil
}
