package safechain

import (
	"context"
	"fmt"
	"log"

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

func (s *SafechainScanner) Version(ctx context.Context) string {
	output, err := platform.RunAsCurrentUser(ctx, platform.GetConfig().SafeChainBinaryPath, []string{"-v"})
	if err != nil {
		return ""
	}

	var version string
	_, err = fmt.Sscanf(string(output), "Current safe-chain version: %s", &version)
	if err != nil {
		return ""
	}

	return version
}

func (s *SafechainScanner) Install(ctx context.Context) error {
	log.Printf("Installing safe-chain via install script...")

	version, err := utils.FetchLatestVersion(ctx, repoURL, "install-safe-chain.sh")
	if err != nil {
		return fmt.Errorf("failed to fetch latest version: %w", err)
	}
	log.Printf("Latest safe-chain version: %s", version)

	if err := platform.InstallSafeChain(ctx, repoURL, version); err != nil {
		return fmt.Errorf("failed to install safe-chain: %w", err)
	}

	return nil
}

func (s *SafechainScanner) Uninstall(ctx context.Context) error {
	log.Printf("Uninstalling safe-chain via uninstall script...")

	version := s.Version(ctx)
	if version == "" {
		return fmt.Errorf("safe-chain version not set, cannot uninstall")
	}

	if err := platform.UninstallSafeChain(ctx, repoURL, version); err != nil {
		return fmt.Errorf("failed to uninstall safe-chain: %w", err)
	}

	return nil
}

func (s *SafechainScanner) IsInstalled(ctx context.Context) bool {
	return s.Version(ctx) != ""
}
