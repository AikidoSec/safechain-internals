package set_system_proxy

import (
	"context"
	"fmt"
	"log"

	"github.com/AikidoSec/safechain-agent/internal/platform"
	"github.com/AikidoSec/safechain-agent/internal/proxy"
)

type Step struct {
}

func New() *Step {
	return &Step{}
}

func (s *Step) InstallName() string {
	return "Set System Proxy"
}

func (s *Step) InstallDescription() string {
	return "Configures the system-level proxy to route traffic through SafeChain Proxy"
}

func (s *Step) UninstallName() string {
	return "Remove System Proxy"
}

func (s *Step) UninstallDescription() string {
	return "Removes the system-level proxy configuration that routes traffic through SafeChain Proxy"
}

func (s *Step) Install(ctx context.Context) error {
	err := proxy.LoadProxyConfig()
	if err != nil {
		return fmt.Errorf("failed to load proxy config: %v", err)
	}
	if err := platform.SetSystemProxy(ctx, proxy.ProxyHttpUrl); err != nil {
		return fmt.Errorf("failed to set system proxy: %v", err)
	}
	if err := platform.IsSystemProxySet(ctx, proxy.ProxyHttpUrl); err != nil {
		return fmt.Errorf("could not verify if system proxy is set: %v", err)
	}
	log.Println("System proxy set successfully")
	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	return platform.UnsetSystemProxy(ctx)
}
