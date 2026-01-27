package set_system_proxy

import (
	"context"
	"fmt"
	"log"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

type Step struct {
}

func New() *Step {
	return &Step{}
}

func (s *Step) InstallName() string {
	return "Set System PAC"
}

func (s *Step) InstallDescription() string {
	return "Configures the system-level PAC to route traffic through SafeChain Proxy"
}

func (s *Step) UninstallName() string {
	return "Remove System PAC"
}

func (s *Step) UninstallDescription() string {
	return "Removes the system-level PAC configuration that routes traffic through SafeChain Proxy"
}

func (s *Step) Install(ctx context.Context) error {
	err := proxy.LoadProxyConfig()
	if err != nil {
		return fmt.Errorf("failed to load proxy config: %v", err)
	}
	proxySet, err := platform.IsAnySystemProxySet(ctx)
	if err != nil {
		return fmt.Errorf("failed to check if any system proxy is set: %v", err)
	}
	if proxySet {
		return fmt.Errorf("system proxy/pac is already set! Failing installation to avoid proxy conflicts!")
	}
	if err := platform.SetSystemPAC(ctx, proxy.MetaPacURL); err != nil {
		return fmt.Errorf("failed to set system PAC: %v", err)
	}
	if err := platform.IsSystemPACSet(ctx, proxy.MetaPacURL); err != nil {
		return fmt.Errorf("could not verify if system PAC is set: %v", err)
	}
	log.Println("System PAC set successfully")
	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	if err := platform.IsSystemPACSet(ctx, proxy.MetaPacURL); err != nil {
		return fmt.Errorf("system PAC is not set! Failing uninstallation to avoid proxy conflicts!")
	}
	return platform.UnsetSystemPAC(ctx, proxy.MetaPacURL)
}
