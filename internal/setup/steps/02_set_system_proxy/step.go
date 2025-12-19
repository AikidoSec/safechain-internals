package set_system_proxy

import (
	"context"
	"fmt"

	"github.com/AikidoSec/safechain-agent/internal/platform"
	"github.com/AikidoSec/safechain-agent/internal/proxy"
)

type Step struct {
}

func New() *Step {
	return &Step{}
}

func (s *Step) Name() string {
	return "Set System Proxy"
}

func (s *Step) Description() string {
	return "Configures the system-level proxy to route traffic through Safe Chain Agent"
}

func (s *Step) Run(ctx context.Context) error {
	err := proxy.LoadProxyConfig()
	if err != nil {
		return fmt.Errorf("failed to load proxy config: %v", err)
	}
	return platform.SetSystemProxy(ctx, proxy.ProxyHttpUrl)
}
