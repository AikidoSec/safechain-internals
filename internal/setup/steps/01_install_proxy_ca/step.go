package install_proxy_ca

import (
	"context"
	"fmt"
	"log"
	"path/filepath"

	"github.com/AikidoSec/safechain-agent/internal/platform"
	"github.com/AikidoSec/safechain-agent/internal/proxy"
	"github.com/AikidoSec/safechain-agent/internal/utils"
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
	return "Install Proxy CA"
}

func (s *Step) Description() string {
	return "Installs the SafeChain Proxy certificate authority to the system"
}

func (s *Step) DownloadCACertFromProxy() error {
	metaUrl, _, err := proxy.GetMetaUrl()
	if err != nil {
		return fmt.Errorf("failed to get meta url: %v", err)
	}

	config := platform.GetConfig()
	caCertPath := filepath.Join(config.RunDir, "safechain-proxy", "safechain-proxy-ca-crt.pem")
	if err := utils.DownloadBinary(context.Background(), metaUrl+"/ca", caCertPath); err != nil {
		return fmt.Errorf("failed to download ca cert: %v", err)
	}

	log.Println("Downloaded CA cert from proxy:", caCertPath)
	return nil
}

func (s *Step) GetCaCertPath() string {
	config := platform.GetConfig()
	return filepath.Join(config.RunDir, "safechain-proxy", "safechain-proxy-ca-crt.pem")
}

func (s *Step) Install(ctx context.Context) error {
	if err := s.DownloadCACertFromProxy(); err != nil {
		return err
	}
	if err := platform.InstallProxyCA(ctx, s.GetCaCertPath()); err != nil {
		return fmt.Errorf("failed to install ca cert: %v", err)
	}
	if err := platform.CheckProxyCA(ctx, s.GetCaCertPath()); err != nil {
		return fmt.Errorf("failed to check ca cert: %v", err)
	}
	log.Println("Installed CA cert successfully")
	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	if err := platform.UninstallProxyCA(ctx); err != nil {
		return fmt.Errorf("failed to uninstall ca cert: %v", err)
	}
	log.Println("Uninstalled CA cert successfully")
	return nil
}

func (s *Step) Run(ctx context.Context) error {
	if s.uninstall {
		return s.Uninstall(ctx)
	}
	return s.Install(ctx)
}
