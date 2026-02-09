package configure_maven

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const (
	aikidoProxyHTTPID  = "aikido-proxy-http"
	aikidoProxyHTTPSID = "aikido-proxy-https"
	markerStart        = "<!-- aikido-safe-chain-start -->"
	markerEnd          = "<!-- aikido-safe-chain-end -->"
)

// hasAikidoProxies checks if the content already contains Aikido proxies
func hasAikidoProxies(content string) bool {
	return strings.Contains(content, markerStart)
}

// buildProxyBlock creates the Aikido proxy XML block with markers
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

// buildSettingsWithProxies creates a complete settings.xml from scratch with Aikido proxies
func buildSettingsWithProxies(host, port string) (string, error) {
	proxyBlock := buildProxyBlock(host, port)
	settings := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
<proxies>
%s</proxies>
</settings>`, proxyBlock)

	// Validate the result is well-formed XML
	if err := validateXMLWellFormedness(settings); err != nil {
		return "", fmt.Errorf("generated XML is not well-formed: %v", err)
	}

	return settings, nil
}

// addAikidoProxies inserts Aikido proxy entries using string manipulation
func addAikidoProxies(content string, host, port string) (string, error) {
	// Build the proxy entries with markers
	proxyBlock := buildProxyBlock(host, port)

	var result string

	// Check if <proxies> block already exists
	if strings.Contains(content, "<proxies>") {
		// Insert entries at the top of existing <proxies> block
		result = strings.Replace(content, "<proxies>", "<proxies>\n"+proxyBlock, 1)
	} else {
		// Create new <proxies> block before </settings>
		proxiesBlock := fmt.Sprintf("<proxies>\n%s</proxies>\n", proxyBlock)
		result = strings.Replace(content, "</settings>", proxiesBlock+"</settings>", 1)
	}

	// Validate the result is well-formed XML
	if err := validateXMLWellFormedness(result); err != nil {
		return "", fmt.Errorf("generated XML is not well-formed: %v", err)
	}

	return result, nil
}

// removeAikidoProxies removes Aikido proxy entries by removing everything between markers
func removeAikidoProxies(content string) (string, bool, error) {
	// Find the start marker
	startIdx := strings.Index(content, markerStart)
	if startIdx == -1 {
		return content, false, nil // No Aikido proxies found
	}

	// Find the end marker
	endIdx := strings.Index(content, markerEnd)
	if endIdx == -1 {
		return "", false, fmt.Errorf("found start marker but not end marker - corrupt configuration")
	}

	if endIdx <= startIdx {
		return "", false, fmt.Errorf("end marker appears before start marker - corrupt configuration")
	}

	// Calculate the end position (inclusive of the marker)
	endPos := endIdx + len(markerEnd)

	// Remove trailing newline if present
	if endPos < len(content) && content[endPos] == '\n' {
		endPos++
	}

	// Remove everything from start to end
	result := content[:startIdx] + content[endPos:]

	// Validate the result is well-formed XML
	if err := validateXMLWellFormedness(result); err != nil {
		return "", false, fmt.Errorf("result XML is not well-formed: %v", err)
	}

	return result, true, nil
}

// validateXMLWellFormedness checks if the XML is well-formed by parsing all tokens
func validateXMLWellFormedness(content string) error {
	decoder := xml.NewDecoder(strings.NewReader(content))

	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("XML parsing error: %v", err)
		}
	}

	return nil
}
