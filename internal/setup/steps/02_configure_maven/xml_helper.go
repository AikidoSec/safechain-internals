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
	xmlProxiesStart    = "<proxies>"
	xmlProxiesEnd      = "</proxies>"
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

func addAikidoProxies(content string, host, port string) (string, error) {
	proxyBlock := buildProxyBlock(host, port)

	var result string

	// Add proxies
	if strings.Contains(content, xmlProxiesStart) {
		result = strings.Replace(content, xmlProxiesStart, xmlProxiesStart+"\n"+proxyBlock, 1)
	} else {
		proxiesBlock := fmt.Sprintf("%s\n%s%s\n", xmlProxiesStart, proxyBlock, xmlProxiesEnd)
		result = strings.Replace(content, "</settings>", proxiesBlock+"</settings>", 1)
	}

	if err := validateXMLWellFormedness(result); err != nil {
		return "", fmt.Errorf("generated XML is not well-formed: %v", err)
	}

	return result, nil
}

func removeAikidoMavenOverrides(content string) (string, bool, error) {
	result, removed, err := removeAikidoBlock(content, markerStart, markerEnd)
	if err != nil {
		return "", false, err
	}

	if !removed {
		return content, false, nil
	}

	if err := validateXMLWellFormedness(result); err != nil {
		return "", false, fmt.Errorf("result XML is not well-formed: %v", err)
	}

	return result, true, nil
}

func removeAikidoBlock(content, startMarker, endMarker string) (string, bool, error) {
	startIdx := strings.Index(content, startMarker)
	if startIdx == -1 {
		return content, false, nil
	}

	endIdx := strings.Index(content, endMarker)
	if endIdx == -1 {
		return "", false, fmt.Errorf("found start marker but not end marker - corrupt configuration")
	}

	if endIdx <= startIdx {
		return "", false, fmt.Errorf("end marker appears before start marker - corrupt configuration")
	}

	endPos := endIdx + len(endMarker)
	if endPos < len(content) && content[endPos] == '\n' {
		endPos++
	}

	result := content[:startIdx] + content[endPos:]
	return result, true, nil
}

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
