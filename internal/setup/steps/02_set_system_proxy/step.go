package set_system_proxy

import (
	"context"
	"fmt"

	"github.com/AikidoSec/safechain-agent/internal/platform"
	"github.com/AikidoSec/safechain-agent/internal/proxy"
)

type Step struct {
	uninstall bool
}

func New(uninstall bool) *Step {
	return &Step{
		uninstall: uninstall,
	}
}

func (s *Step) Name() string {
	if s.uninstall {
		return "Remove System Proxy"
	}
	return "Set System Proxy"
}

func (s *Step) Description() string {
	if s.uninstall {
		return "Removes the system-level proxy configuration"
	}
	return "Configures the system-level proxy to route traffic through Safe Chain Agent"
}

func (s *Step) Run(ctx context.Context) error {
	if s.uninstall {
		return s.Uninstall(ctx)
	}
	return s.Install(ctx)
}

func (s *Step) Uninstall(ctx context.Context) error {
	return platform.UnsetSystemProxy(ctx)
}

func (s *Step) Install(ctx context.Context) error {
	err := proxy.LoadProxyConfig()
	if err != nil {
		return fmt.Errorf("failed to load proxy config: %v", err)
	}
	return platform.SetSystemProxy(ctx, proxy.ProxyHttpUrl)
}
