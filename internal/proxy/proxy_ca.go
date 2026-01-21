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

func DownloadCACertFromProxy() error {
	metaUrl, _, err := GetMetaUrl()
	if err != nil {
		return fmt.Errorf("failed to get meta url: %v", err)
	}

	caCertPath := filepath.Join(platform.GetRunDir(), "safechain-proxy-ca-crt.pem")
	if err := utils.DownloadBinary(context.Background(), metaUrl+"/ca", caCertPath); err != nil {
		return fmt.Errorf("failed to download ca cert: %v", err)
	}

	log.Println("Downloaded CA cert from proxy:", caCertPath)
	return nil
}

func GetCaCertPath() string {
	return filepath.Join(platform.GetRunDir(), "safechain-proxy-ca-crt.pem")
}

func InstallProxyCA(ctx context.Context) error {
	log.Println("Installing proxy CA...")
	if err := DownloadCACertFromProxy(); err != nil {
		return err
	}
	if err := platform.InstallProxyCA(ctx, GetCaCertPath()); err != nil {
		return fmt.Errorf("failed to install ca cert: %v", err)
	}
	if err := CreateProxyCAInstalledMarker(); err != nil {
		return fmt.Errorf("failed to create proxy CA installed marker: %v", err)
	}

	log.Println("Installed CA cert successfully")
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
