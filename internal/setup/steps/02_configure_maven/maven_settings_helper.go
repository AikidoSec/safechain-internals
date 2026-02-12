package configure_maven

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	aikidoProxyHTTPID  = "aikido-proxy-http"
	aikidoProxyHTTPSID = "aikido-proxy-https"
	markerStart        = "<!-- aikido-safe-chain-start -->"
	markerEnd          = "<!-- aikido-safe-chain-end -->"
	xmlProxiesStart    = "<proxies>"
	xmlProxiesEnd      = "</proxies>"

	dirPerm  = 0o755
	filePerm = 0o644

	defaultSettingsTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
</settings>`
)

// Match an opening <proxies ...> tag.
var proxiesOpenTagRE = regexp.MustCompile(`(?i)<\s*proxies\b[^>]*>`)

func ensureDirForFile(path string) error {
	return os.MkdirAll(filepath.Dir(path), dirPerm)
}

func readOrDefaultSettings(settingsPath string) (string, error) {
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		return string(data), nil
	}
	if os.IsNotExist(err) {
		return defaultSettingsTemplate, nil
	}
	return "", fmt.Errorf("failed to read settings.xml: %w", err)
}

func installMavenProxySetting(homeDir, host, port string) error {
	settingsPath := filepath.Join(homeDir, ".m2", "settings.xml")

	if err := ensureDirForFile(settingsPath); err != nil {
		return fmt.Errorf("failed to create settings directory: %w", err)
	}

	content, err := readOrDefaultSettings(settingsPath)
	if err != nil {
		return err
	}

	stripped, _, err := stripProxyFromSettings(content)
	if err != nil {
		return err
	}
	content = stripped

	result, err := applyProxyToSettings(content, host, port)
	if err != nil {
		return err
	}

	return os.WriteFile(settingsPath, []byte(result), filePerm)
}

func uninstallMavenProxySetting(homeDir string) error {
	settingsPath := filepath.Join(homeDir, ".m2", "settings.xml")

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read settings.xml: %w", err)
	}

	newContent, removed, err := stripProxyFromSettings(string(data))
	if err != nil {
		return err
	}
	if !removed {
		return nil
	}

	return os.WriteFile(settingsPath, []byte(newContent), filePerm)
}

func applyProxyToSettings(content, host, port string) (string, error) {
	if err := validateProxyInputs(host, port); err != nil {
		return "", err
	}

	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)

	proxyBlock := buildProxyBlock(host, port)

	result, err := insertProxyBlock(content, proxyBlock)
	if err != nil {
		return "", err
	}

	if err := validateXMLWellFormedness(result); err != nil {
		return "", err
	}

	return result, nil
}

func insertProxyBlock(content, proxyBlock string) (string, error) {
	if loc := proxiesOpenTagRE.FindStringIndex(content); loc != nil {
		openTag := content[loc[0]:loc[1]]
		if isSelfClosingTag(openTag) {
			replacement := xmlProxiesStart + "\n" + proxyBlock + xmlProxiesEnd
			return content[:loc[0]] + replacement + content[loc[1]:], nil
		}

		// Normal <proxies ...> tag: insert immediately after it.
		insertAt := loc[1]
		return content[:insertAt] + "\n" + proxyBlock + content[insertAt:], nil
	}

	// 3) No proxies section at all: insert one before </settings>.
	closeIdx := strings.LastIndex(content, "</settings>")
	if closeIdx == -1 {
		return "", fmt.Errorf("invalid settings.xml: missing </settings> closing tag")
	}

	proxiesSection := xmlProxiesStart + "\n" + proxyBlock + xmlProxiesEnd + "\n"
	return content[:closeIdx] + proxiesSection + content[closeIdx:], nil
}

func isSelfClosingTag(tag string) bool {
	// Works for "<proxies/>", "<proxies />", "<proxies foo='bar'/>", etc.
	tag = strings.TrimSpace(tag)
	return strings.HasSuffix(tag, "/>")
}

func stripProxyFromSettings(content string) (string, bool, error) {
	result, removed, err := removeMarkedBlock(content, markerStart, markerEnd)
	if err != nil {
		return "", false, err
	}
	if !removed {
		return content, false, nil
	}

	if err := validateXMLWellFormedness(result); err != nil {
		return "", false, err
	}

	return result, true, nil
}

func buildProxyBlock(host, port string) string {
	host = xmlEscape(host)
	port = xmlEscape(port)

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

func validateProxyInputs(host, port string) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("invalid proxy host")
	}

	_, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return fmt.Errorf("invalid proxy port")
	}
	return nil
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
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

	after = strings.TrimLeft(after, "\r\n")
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
			return fmt.Errorf("XML parsing error: %w", err)
		}
	}
}
