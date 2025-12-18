package proxy

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-agent/internal/platform"
)

func readProxyConfig(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read proxy config: %v", err)
	}
	return strings.TrimSpace(string(content)), nil
}

func GetProxyUrl() (string, string, error) {
	proxyIpPort, err := readProxyConfig(filepath.Join(platform.Get().SafeChainProxyDir, "proxy.addr.txt"))
	if err != nil {
		return "", "", fmt.Errorf("failed to read proxy config: %v", err)
	}
	return "http://" + proxyIpPort, "https://" + proxyIpPort, nil
}

func GetMetaUrl() (string, string, error) {
	metaIpPort, err := readProxyConfig(filepath.Join(platform.Get().SafeChainProxyDir, "meta.addr.txt"))
	if err != nil {
		return "", "", fmt.Errorf("failed to read meta config: %v", err)
	}
	return "http://" + metaIpPort, "https://" + metaIpPort, nil
}

func Ping(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to ping %s: %v", url, err)
	}
	defer resp.Body.Close()
	return nil
}

func Check() error {
	metaUrls := []string{MetaHttpUrl} //MetaHttpsUrl
	for _, url := range metaUrls {
		if err := Ping(url); err != nil {
			return fmt.Errorf("failed to ping proxy meta: %v", err)
		}
	}
	return nil
}
