//go:build darwin

package platform

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// getWebProxyForService returns whether web proxy is enabled and the server:port string (e.g. "127.0.0.1:56043").
func getWebProxyForService(ctx context.Context, service string) (enabled bool, serverPort string, err error) {
	out, err := exec.CommandContext(ctx, "networksetup", "-getwebproxy", service).Output()
	if err != nil {
		return false, "", err
	}
	return parseNetworksetupProxyOutput(string(out))
}

func getSecureWebProxyForService(ctx context.Context, service string) (enabled bool, serverPort string, err error) {
	out, err := exec.CommandContext(ctx, "networksetup", "-getsecurewebproxy", service).Output()
	if err != nil {
		return false, "", err
	}
	return parseNetworksetupProxyOutput(string(out))
}

func parseNetworksetupProxyOutput(output string) (enabled bool, serverPort string, err error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var server, port string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "Enabled: Yes" {
			enabled = true
		}
		// macOS networksetup outputs "Server:"; accept "Host:" for compatibility
		if strings.HasPrefix(line, "Server: ") {
			server = strings.TrimPrefix(line, "Server: ")
		} else if strings.HasPrefix(line, "Host: ") {
			server = strings.TrimPrefix(line, "Host: ")
		}
		if strings.HasPrefix(line, "Port: ") {
			port = strings.TrimPrefix(line, "Port: ")
		}
	}
	if server != "" && port != "" && port != "0" {
		serverPort = server + ":" + port
	}
	return enabled, serverPort, nil
}

func getPACForService(ctx context.Context, service string) (enabled bool, pacURL string, err error) {
	out, err := exec.CommandContext(ctx, "networksetup", "-getautoproxyurl", service).Output()
	if err != nil {
		return false, "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "Enabled: Yes" {
			enabled = true
		}
		if strings.HasPrefix(line, "URL: ") {
			pacURL = strings.TrimPrefix(line, "URL: ")
		}
	}
	return enabled, pacURL, nil
}

// GetSystemProxyConflictDetails returns a human-readable list of which network services
// have a proxy or PAC configured, so the installer can report why "proxy already set" failed.
func GetSystemProxyConflictDetails(ctx context.Context) ([]string, error) {
	services, err := getNetworkServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get network services: %v", err)
	}
	var details []string
	for _, service := range services {
		var parts []string
		if enabled, serverPort, err := getWebProxyForService(ctx, service); err == nil && enabled {
			if serverPort != "" {
				parts = append(parts, "Web Proxy "+serverPort)
			} else {
				parts = append(parts, "Web Proxy enabled")
			}
		}
		if enabled, serverPort, err := getSecureWebProxyForService(ctx, service); err == nil && enabled {
			if serverPort != "" {
				parts = append(parts, "Secure Web Proxy "+serverPort)
			} else {
				parts = append(parts, "Secure Web Proxy enabled")
			}
		}
		if enabled, pacURL, err := getPACForService(ctx, service); err == nil && enabled {
			if pacURL != "" && pacURL != "(null)" {
				parts = append(parts, "PAC "+pacURL)
			} else {
				parts = append(parts, "PAC enabled")
			}
		}
		if len(parts) > 0 {
			details = append(details, fmt.Sprintf("  - %q: %s", service, strings.Join(parts, ", ")))
		}
	}
	return details, nil
}
