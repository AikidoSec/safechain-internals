package proxy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-agent/internal/platform"
)

var (
	ProxyHttpUrl  string
	ProxyHttpsUrl string
	MetaHttpUrl   string
	MetaHttpsUrl  string
)

func readProxyConfig(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read proxy config: %v", err)
	}
	return strings.TrimSpace(string(content)), nil
}

func GetProxyUrl() (string, string, error) {
	proxyIpPort, err := readProxyConfig(filepath.Join(platform.GetConfig().RunDir, "safechain-proxy", "proxy.addr.txt"))
	if err != nil {
		return "", "", fmt.Errorf("failed to read proxy config: %v", err)
	}
	return "http://" + proxyIpPort, "https://" + proxyIpPort, nil
}

func GetMetaUrl() (string, string, error) {
	metaIpPort, err := readProxyConfig(filepath.Join(platform.GetConfig().RunDir, "safechain-proxy", "meta.addr.txt"))
	if err != nil {
		return "", "", fmt.Errorf("failed to read meta config: %v", err)
	}
	return "http://" + metaIpPort, "https://" + metaIpPort, nil
}

func Ping(url string) error {
	resp, err := http.Get(url + "/ping")
	if err != nil {
		return fmt.Errorf("failed to ping %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to ping %s: %v", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body from %s: %v", url, err)
	}

	if !strings.Contains(string(body), "pong") {
		return fmt.Errorf("unexpected response from %s: expected 'pong', got: %s", url, string(body))
	}
	return nil
}

func CheckProxy() error {
	metaUrls := []string{MetaHttpUrl} //MetaHttpsUrl
	for _, url := range metaUrls {
		if err := Ping(url); err != nil {
			return fmt.Errorf("failed to ping proxy meta: %v", err)
		}
	}
	return nil
}

func LoadProxyConfig() error {
	var err error
	ProxyHttpUrl, ProxyHttpsUrl, err = GetProxyUrl()
	if err != nil {
		return fmt.Errorf("failed to get proxy url: %v", err)
	}
	MetaHttpUrl, MetaHttpsUrl, err = GetMetaUrl()
	if err != nil {
		return fmt.Errorf("failed to get meta url: %v", err)
	}

	return nil
}
