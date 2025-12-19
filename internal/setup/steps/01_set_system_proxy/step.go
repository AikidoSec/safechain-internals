package setsystemproxy

import (
	"context"

	"github.com/AikidoSec/safechain-agent/internal/platform"
)

type Step struct {
	proxyURL string
}

func New(proxyURL string) *Step {
	return &Step{proxyURL: proxyURL}
}

func (s *Step) Name() string {
	return "Set System Proxy"
}

func (s *Step) Description() string {
	return "Configures the system-level proxy to route traffic through Safe Chain Agent"
}

func (s *Step) Run(ctx context.Context) error {
	return platform.SetSystemProxy(ctx, s.proxyURL)
}
