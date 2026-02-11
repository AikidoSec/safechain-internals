package configure_maven

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

const (
	aikidoMavenOptsBegin = "# AIKIDO SAFECHAIN MAVEN_OPTS BEGIN"
	aikidoMavenOptsEnd   = "# AIKIDO SAFECHAIN MAVEN_OPTS END"
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

	// Add new MAVEN_OPTS (wrapped in Aikido markers so we can safely remove it later)
	block := fmt.Sprintf(
		"%s\nexport MAVEN_OPTS=\"%s\"\n%s\n",
		aikidoMavenOptsBegin,
		mavenOpts,
		aikidoMavenOptsEnd,
	)
	content = strings.TrimRight(content, "\n")
	if content != "" {
		content += "\n"
	}
	content += block

	// Write to file
	return os.WriteFile(path, []byte(content), 0644)
}

func removeMavenrc(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	content := removeExistingMavenOpts(string(data))

	return os.WriteFile(path, []byte(content), 0644)
}

// removeExistingMavenOpts removes Aikido's MAVEN_OPTS content from .mavenrc content.
//
// Removal is done via the marker-wrapped block.
func removeExistingMavenOpts(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inAikidoBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Remove marker-wrapped block
		if trimmed == aikidoMavenOptsBegin {
			inAikidoBlock = true
			continue
		}
		if inAikidoBlock {
			if trimmed == aikidoMavenOptsEnd {
				inAikidoBlock = false
			}
			continue
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}
