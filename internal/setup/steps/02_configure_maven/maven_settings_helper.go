package configure_maven

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	aikidoProxyHTTPID  = "aikido-proxy-http"
	aikidoProxyHTTPSID = "aikido-proxy-https"
	markerStart        = "<!-- aikido-safe-chain-start -->"
	markerEnd          = "<!-- aikido-safe-chain-end -->"
	xmlProxiesStart    = "<proxies>"
	xmlProxiesEnd      = "</proxies>"

	defaultSettingsTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
</settings>`
)

func installMavenProxySetting(homeDir, host, port string) error {
	settingsPath := filepath.Join(homeDir, ".m2", "settings.xml")

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0755); err != nil {
		return fmt.Errorf("failed to create settings directory: %v", err)
	}

	content := defaultSettingsTemplate
	if data, err := os.ReadFile(settingsPath); err == nil {
		content = string(data)
	}

	if stripped, _, err := stripProxyFromSettings(content); err == nil {
		content = stripped
	}

	result, err := applyProxyToSettings(content, host, port)
	if err != nil {
		return err
	}

	if !strings.Contains(result, markerStart) {
		return fmt.Errorf("failed to apply proxy settings: marker not found in result")
	}

	return os.WriteFile(settingsPath, []byte(result), 0644)
}

func uninstallMavenProxySetting(homeDir string) error {
	settingsPath := filepath.Join(homeDir, ".m2", "settings.xml")

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read settings.xml: %v", err)
	}

	newContent, removed, err := stripProxyFromSettings(string(data))
	if !removed || err != nil {
		return err
	}

	return os.WriteFile(settingsPath, []byte(newContent), 0644)
}

func applyProxyToSettings(content, host, port string) (string, error) {
	proxyBlock := buildProxyBlock(host, port)

	var result string
	if strings.Contains(content, xmlProxiesStart) {
		result = strings.Replace(content, xmlProxiesStart, xmlProxiesStart+"\n"+proxyBlock, 1)
	} else {
		if !strings.Contains(content, "</settings>") {
			return "", fmt.Errorf("invalid settings.xml: missing </settings> closing tag")
		}
		proxiesBlock := fmt.Sprintf("%s\n%s%s\n", xmlProxiesStart, proxyBlock, xmlProxiesEnd)
		result = strings.Replace(content, "</settings>", proxiesBlock+"</settings>", 1)
	}

	if err := validateXMLWellFormedness(result); err != nil {
		return "", err
	}

	return result, nil
}

func stripProxyFromSettings(content string) (string, bool, error) {
	result, removed, err := removeMarkedBlock(content, markerStart, markerEnd)
	if !removed || err != nil {
		return content, false, err
	}

	if err := validateXMLWellFormedness(result); err != nil {
		return "", false, err
	}

	return result, true, nil
}

func buildProxyBlock(host, port string) string {
	return fmt.Sprintf(`%s
  <proxy>
    <id>%s</id>
    <active>true</active>
    <protocol>http</protocol>
    <host>%s</host>
    <port>%s</port>
  </proxy>
  <proxy>
    <id>%s</id>
    <active>true</active>
    <protocol>https</protocol>
    <host>%s</host>
    <port>%s</port>
  </proxy>
  %s
`, markerStart, aikidoProxyHTTPID, host, port, aikidoProxyHTTPSID, host, port, markerEnd)
}

func removeMarkedBlock(content, startMarker, endMarker string) (string, bool, error) {
	before, rest, found := strings.Cut(content, startMarker)
	if !found {
		return content, false, nil
	}

	_, after, found := strings.Cut(rest, endMarker)
	if !found {
		return "", false, fmt.Errorf("found start marker but not end marker - corrupt configuration")
	}

	after = strings.TrimPrefix(after, "\r\n")
	after = strings.TrimPrefix(after, "\n")
	return before + after, true, nil
}

func validateXMLWellFormedness(content string) error {
	decoder := xml.NewDecoder(strings.NewReader(content))

	for {
		_, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("XML parsing error: %v", err)
		}
	}
}
