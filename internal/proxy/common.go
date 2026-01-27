package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

var (
	ProxyHttpUrl  string
	ProxyHttpsUrl string
	MetaHttpUrl   string
	MetaHttpsUrl  string
	MetaPacURL    string
)

func readProxyConfig(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read proxy config: %v", err)
	}
	return strings.TrimSpace(string(content)), nil
}

func GetProxyUrls() (string, string, error) {
	proxyAddress, err := readProxyConfig(filepath.Join(platform.GetRunDir(), "proxy.addr.txt"))
	if err != nil {
		return "", "", fmt.Errorf("failed to read proxy config: %v", err)
	}
	return "http://" + proxyAddress, "https://" + proxyAddress, nil
}

func GetMetaUrls() (string, string, string, error) {
	metaAddress, err := readProxyConfig(filepath.Join(platform.GetRunDir(), "meta.addr.txt"))
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read meta config: %v", err)
	}
	parsed, err := url.Parse(metaAddress)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse address: %v", err)
	}
	metaUrlHttp := "http://" + metaAddress
	metaUrlHttps := "https://" + metaAddress
	metaUrlPac := "https://localhost:" + parsed.Port() + "/pac"
	return metaUrlHttp, metaUrlHttps, metaUrlPac, nil
}

func Ping(url string) error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(url + "/ping")
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

func IsProxyRunning() bool {
	metaUrls := []string{MetaHttpUrl, MetaHttpsUrl}
	for _, url := range metaUrls {
		if err := Ping(url); err != nil {
			log.Println("Proxy not running:", err)
			return false
		}
	}
	return true
}

func LoadProxyConfig() error {
	var err error
	ProxyHttpUrl, ProxyHttpsUrl, err = GetProxyUrls()
	if err != nil {
		return fmt.Errorf("failed to get proxy url: %v", err)
	}
	MetaHttpUrl, MetaHttpsUrl, MetaPacURL, err = GetMetaUrls()
	if err != nil {
		return fmt.Errorf("failed to get meta url: %v", err)
	}

	return nil
}
