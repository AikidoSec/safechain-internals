package install_proxy_ca

import (
	"context"
	"path/filepath"

	"github.com/AikidoSec/safechain-agent/internal/platform"
)

type Step struct {
}

func New() *Step {
	return &Step{}
}

func (s *Step) Name() string {
	return "Install Proxy CA"
}

func (s *Step) Description() string {
	return "Installs the proxy CA to the system"
}

func (s *Step) GetCaCertPath() string {
	config := platform.GetConfig()
	return filepath.Join(config.RunDir, "safechain-proxy", "ca-crt.pem")
}

func (s *Step) Run(ctx context.Context) error {
	return platform.InstallProxyCA(ctx, s.GetCaCertPath())
}
