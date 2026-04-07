package configure_chrome_proxy

import (
	"context"
	"fmt"
	"log"

	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

type Step struct{}

func New() *Step {
	return &Step{}
}

func (s *Step) InstallName() string {
	return "Configure Chrome Proxy"
}

func (s *Step) InstallDescription() string {
	return "Configures Chrome to route traffic through SafeChain Proxy via managed policy"
}

func (s *Step) UninstallName() string {
	return "Remove Chrome Proxy"
}

func (s *Step) UninstallDescription() string {
	return "Removes Chrome managed policy that routes traffic through SafeChain Proxy"
}

func (s *Step) Install(ctx context.Context) error {
	if err := installChromeProxy(ctx, proxy.L7PacURL()); err != nil {
		return fmt.Errorf("failed to configure Chrome proxy: %w", err)
	}
	log.Println("Chrome proxy configured successfully")
	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	if err := uninstallChromeProxy(ctx); err != nil {
		return fmt.Errorf("failed to remove Chrome proxy configuration: %w", err)
	}
	log.Println("Chrome proxy configuration removed")
	return nil
}
