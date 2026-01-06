package install_proxy_ca

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-agent/internal/platform"
	"github.com/AikidoSec/safechain-agent/internal/proxy"
	"github.com/AikidoSec/safechain-agent/internal/utils"
)

type Step struct {
}

func New() *Step {
	return &Step{}
}

func (s *Step) InstallName() string {
	return "Install Proxy CA"
}

func (s *Step) InstallDescription() string {
	return "Installs the Safe Chain Proxy certificate authority"
}

func (s *Step) UninstallName() string {
	return "Uninstall Proxy CA"
}

func (s *Step) UninstallDescription() string {
	return "Uninstalls the SafeChain Proxy certificate authority"
}

func (s *Step) DownloadCACertFromProxy() error {
	metaUrl, _, err := proxy.GetMetaUrl()
	if err != nil {
		return fmt.Errorf("failed to get meta url: %v", err)
	}

	caCertPath := filepath.Join(platform.GetProxyRunDir(), "safechain-proxy-ca-crt.pem")
	if err := utils.DownloadBinary(context.Background(), metaUrl+"/ca", caCertPath); err != nil {
		return fmt.Errorf("failed to download ca cert: %v", err)
	}

	log.Println("Downloaded CA cert from proxy:", caCertPath)
	return nil
}

func (s *Step) GetCaCertPath() string {
	return filepath.Join(platform.GetProxyRunDir(), "safechain-proxy-ca-crt.pem")
}

func (s *Step) Install(ctx context.Context) error {
	if err := s.DownloadCACertFromProxy(); err != nil {
		return err
	}
	if err := platform.InstallProxyCA(ctx, s.GetCaCertPath()); err != nil {
		return fmt.Errorf("failed to install ca cert: %v", err)
	}
	if err := platform.IsProxyCAInstalled(ctx); err != nil {
		return fmt.Errorf("failed to check ca cert: %v", err)
	}
	log.Println("Installed CA cert successfully")
	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	if err := platform.UninstallProxyCA(ctx); err != nil {
		return fmt.Errorf("failed to uninstall ca cert: %v", err)
	}
	if err := os.Remove(s.GetCaCertPath()); err != nil {
		log.Printf("failed to remove ca cert: %v\n", err)
	}
	log.Println("Uninstalled CA cert successfully")
	return nil
}
