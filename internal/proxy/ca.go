package proxy

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

func GetProxyCAInstalledMarker() string {
	return filepath.Join(platform.GetRunDir(), ".proxy_ca_installed")
}

func CreateProxyCAInstalledMarker() error {
	if err := os.WriteFile(GetProxyCAInstalledMarker(), []byte{}, 0644); err != nil {
		return fmt.Errorf("failed to write proxy CA installed marker: %w", err)
	}
	log.Println("Proxy CA installed marker created successfully!")
	return nil
}

func RemoveProxyCAInstalledMarker() error {
	if err := os.Remove(GetProxyCAInstalledMarker()); err != nil {
		return fmt.Errorf("failed to remove proxy CA installed marker: %w", err)
	}
	return nil
}

func ProxyCAInstalled() bool {
	if _, err := os.Stat(GetProxyCAInstalledMarker()); os.IsNotExist(err) {
		return false
	}
	return true
}

const l4HijackCAURL = "http://mitm.ramaproxy.org/data/root.ca.pem"

func DownloadCACertFromL7Proxy() error {
	metaUrl, _, _, err := GetMetaUrls()
	if err != nil {
		return fmt.Errorf("failed to get meta url: %v", err)
	}

	if err := utils.DownloadBinary(context.Background(), metaUrl+"/ca", GetCaCertPath()); err != nil {
		return fmt.Errorf("failed to download ca cert: %v", err)
	}

	log.Println("Downloaded CA cert from proxy:", GetCaCertPath())
	return nil
}

func DownloadCACertFromL4Proxy(ctx context.Context) error {
	if err := utils.DownloadBinary(ctx, l4HijackCAURL, GetCaCertPath()); err != nil {
		return fmt.Errorf("failed to download CA cert from L4 proxy: %v", err)
	}

	log.Println("Downloaded CA cert from L4 proxy:", GetCaCertPath())
	return nil
}

func GetCaCertPath() string {
	return filepath.Join(platform.GetRunDir(), "endpoint-protection-proxy-ca-crt.pem")
}

func installDownloadedProxyCA(ctx context.Context) error {
	if err := platform.InstallProxyCA(ctx, GetCaCertPath()); err != nil {
		return fmt.Errorf("failed to install ca cert: %v", err)
	}
	if err := CreateProxyCAInstalledMarker(); err != nil {
		return fmt.Errorf("failed to create proxy CA installed marker: %v", err)
	}

	log.Println("Installed CA cert successfully")
	return nil
}

func InstallL7ProxyCA(ctx context.Context) error {
	log.Println("Installing L7 proxy CA...")
	if err := DownloadCACertFromL7Proxy(); err != nil {
		return err
	}
	return installDownloadedProxyCA(ctx)
}

func InstallL4ProxyCA(ctx context.Context) error {
	log.Println("Installing L4 proxy CA...")
	if err := DownloadCACertFromL4Proxy(ctx); err != nil {
		return err
	}
	return installDownloadedProxyCA(ctx)
}

func GetL7CaCertPath() string {
	return filepath.Join(platform.GetRunDir(), "endpoint-protection-l7-proxy-ca-crt.pem")
}

// InstallL7ProxyCAAsAdditional downloads the L7 CA cert and installs it into
// the OS keychain alongside the primary proxy CA. Used in l4-chrome-l7 mode
// so Chrome trusts L7's MITM certificates while L4's CA remains the primary
// cert for ecosystem tools (npm, pip, vscode).
func InstallL7ProxyCAAsAdditional(ctx context.Context) error {
	log.Println("Installing L7 proxy CA as additional trusted cert...")
	metaUrl, _, _, err := GetMetaUrls()
	if err != nil {
		return fmt.Errorf("failed to get L7 meta url: %w", err)
	}
	if err := utils.DownloadBinary(ctx, metaUrl+"/ca", GetL7CaCertPath()); err != nil {
		return fmt.Errorf("failed to download L7 CA cert: %w", err)
	}
	if err := platform.InstallProxyCA(ctx, GetL7CaCertPath()); err != nil {
		return fmt.Errorf("failed to install L7 CA cert: %w", err)
	}
	log.Println("L7 proxy CA installed as additional trusted cert successfully")
	return nil
}

func UninstallProxyCA(ctx context.Context) error {
	if err := platform.UninstallProxyCA(ctx); err != nil {
		return fmt.Errorf("failed to uninstall ca cert: %v", err)
	}
	if err := os.Remove(GetCaCertPath()); err != nil {
		log.Printf("failed to remove ca cert: %v\n", err)
	}
	if err := RemoveProxyCAInstalledMarker(); err != nil {
		return fmt.Errorf("failed to remove proxy CA installed marker: %v", err)
	}
	log.Println("Uninstalled CA cert successfully")
	return nil
}
