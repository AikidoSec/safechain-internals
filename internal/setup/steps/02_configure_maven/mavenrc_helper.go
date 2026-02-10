package configure_maven

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

func createMavenrc(path string) error {
	var mavenOpts string
	switch runtime.GOOS {
	case "darwin":
		mavenOpts = "-Djavax.net.ssl.trustStoreType=KeychainStore"
	case "windows":
		mavenOpts = "-Djavax.net.ssl.trustStoreType=Windows-Root"
	default:
		mavenOpts = "-Djavax.net.ssl.trustStore=/etc/ssl/certs/ca-certificates.crt"
	}

	// Read existing .mavenrc if it exists
	var content string
	if data, err := os.ReadFile(path); err == nil {
		content = string(data)
	}

	// Remove existing Aikido MAVEN_OPTS if present
	content = removeExistingMavenOpts(content)

	// Add new MAVEN_OPTS
	mavenOptsLine := fmt.Sprintf("export MAVEN_OPTS=\"%s\"\n", mavenOpts)
	content = strings.TrimRight(content, "\n") + "\n" + mavenOptsLine

	// Write to file
	return os.WriteFile(path, []byte(content), 0644)
}

// removeMavenrc removes the Aikido MAVEN_OPTS from .mavenrc
func removeMavenrc(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	content := removeExistingMavenOpts(string(data))

	// If file is now empty or only whitespace, remove it
	if strings.TrimSpace(content) == "" {
		return os.Remove(path)
	}

	return os.WriteFile(path, []byte(content), 0644)
}

// removeExistingMavenOpts removes Aikido's MAVEN_OPTS lines from .mavenrc content
func removeExistingMavenOpts(content string) string {
	lines := strings.Split(content, "\n")
	var result []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip lines that are Aikido's MAVEN_OPTS (identified by truststore flags)
		if strings.Contains(trimmed, "javax.net.ssl.trustStoreType") ||
			strings.Contains(trimmed, "javax.net.ssl.trustStore=/etc/ssl/certs") {
			continue
		}
		result = append(result, line)
	}

	return strings.Join(result, "\n")
}
