package uninstall_safechain

import (
	"context"
	"fmt"
	"log"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const repoURL = "https://github.com/AikidoSec/safe-chain"

type Step struct{}

func New() *Step {
	return &Step{}
}

func (s *Step) InstallName() string {
	return "Uninstall safe-chain"
}

func (s *Step) InstallDescription() string {
	return "Removes any existing safe-chain CLI installation from the system"
}

func (s *Step) UninstallName() string {
	return "Uninstall safe-chain"
}

func (s *Step) UninstallDescription() string {
	return "Removes any existing safe-chain CLI installation from the system"
}

func (s *Step) Install(ctx context.Context) error {
	return uninstallSafeChain(ctx)
}

func (s *Step) Uninstall(ctx context.Context) error {
	return uninstallSafeChain(ctx)
}

func uninstallSafeChain(ctx context.Context) error {
	version := installedSafeChainVersion(ctx)
	if version == "" {
		log.Println("safe-chain is not installed; nothing to do")
		return nil
	}

	log.Printf("Detected installed safe-chain version: %s", version)
	if err := platform.UninstallSafeChain(ctx, repoURL, version); err != nil {
		return fmt.Errorf("failed to uninstall safe-chain: %w", err)
	}
	log.Println("safe-chain uninstalled successfully")
	return nil
}

func installedSafeChainVersion(ctx context.Context) string {
	output, err := platform.RunAsCurrentUser(context.WithValue(ctx, "disable_logging", true), platform.GetConfig().SafeChainBinaryPath, []string{"-v"})
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
