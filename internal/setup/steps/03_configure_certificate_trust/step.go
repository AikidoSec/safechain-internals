package configure_certificate_trust

import (
	"context"
	"fmt"
	"log"

	"github.com/AikidoSec/safechain-internals/internal/certconfig"
)

type Step struct{}

func New() *Step {
	return &Step{}
}

func (s *Step) InstallName() string {
	return "Configure Certificate Trust"
}

func (s *Step) InstallDescription() string {
	return "Configures ecosystem-specific trust settings for Node.js, pip, Firefox, Java, Homebrew, and Git"
}

func (s *Step) UninstallName() string {
	return "Restore Certificate Trust Settings"
}

func (s *Step) UninstallDescription() string {
	return "Removes ecosystem-specific trust settings for Node.js, pip, Firefox, Java, Homebrew, and Git"
}

func (s *Step) Install(ctx context.Context) error {
	if err := certconfig.Install(ctx); err != nil {
		return fmt.Errorf("failed to configure certificate trust: %w", err)
	}
	log.Println("Certificate trust configuration complete")
	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	if err := certconfig.Teardown(ctx); err != nil {
		return fmt.Errorf("failed to restore certificate trust configuration: %w", err)
	}
	log.Println("Certificate trust configuration removed")
	return nil
}
