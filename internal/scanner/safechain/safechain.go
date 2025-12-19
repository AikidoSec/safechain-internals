package safechain

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/AikidoSec/safechain-agent/internal/platform"
	"github.com/AikidoSec/safechain-agent/internal/scanner"
	"github.com/AikidoSec/safechain-agent/internal/utils"
)

const (
	repoURL    = "https://github.com/AikidoSec/safe-chain"
	binaryName = "safe-chain"
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
	osName, osExtension := utils.DetectOS()
	archName := utils.DetectArch()
	binaryName := fmt.Sprintf("%s-%s-%s%s", binaryName, osName, archName, osExtension)

	version, err := utils.FetchLatestVersion(ctx, repoURL, binaryName)
	if err != nil {
		return fmt.Errorf("failed to fetch latest version: %w", err)
	}

	log.Printf("Latest safechain version: %s", version)

	cfg := platform.GetConfig()
	binaryPath := cfg.SafeChainBinaryPath
	installDir := filepath.Dir(binaryPath)

	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("failed to create install directory: %w", err)
	}

	downloadURL := fmt.Sprintf("%s/releases/download/%s/%s", repoURL, version, binaryName)

	log.Printf("Downloading safechain binary from %s...", downloadURL)
	if err := utils.DownloadBinary(ctx, downloadURL, binaryPath); err != nil {
		return fmt.Errorf("failed to download binary: %w", err)
	}

	if err := os.Chmod(binaryPath, 0755); err != nil {
		log.Printf("Warning: failed to make binary executable: %v", err)
	}

	if err := platform.PrepareShellEnvironment(ctx); err != nil {
		log.Printf("Warning: failed to prepare shell environment: %v", err)
	}

	args := []string{"setup"}

	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run safe-chain setup: %w", err)
	}

	return nil
}

func (s *SafechainScanner) Uninstall(ctx context.Context) error {
	cfg := platform.GetConfig()
	cmd := exec.CommandContext(ctx, cfg.SafeChainBinaryPath, "teardown")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("Running safe-chain teardown...")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run safe-chain teardown: %w", err)
	}

	return nil
}

func (s *SafechainScanner) IsInstalled(ctx context.Context) (bool, error) {
	cfg := platform.GetConfig()
	_, err := os.Stat(cfg.SafeChainBinaryPath)
	return err == nil, nil
}
