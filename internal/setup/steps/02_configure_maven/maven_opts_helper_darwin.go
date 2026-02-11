//go:build darwin

package configure_maven

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	mavenRcMarkerStart = "# aikido-safe-chain-start"
	mavenRcMarkerEnd   = "# aikido-safe-chain-end"
)

func desiredMavenOptsTokens() []string {
	return []string{
		aikidoMavenOptsMarkerToken,
		"-Djavax.net.ssl.trustStoreType=KeychainStore",
		"-Djavax.net.ssl.trustStore=NONE",
	}
}

func installMavenOptsOverride(_ context.Context, homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")

	content := ""
	if data, err := os.ReadFile(mavenrcPath); err == nil {
		content = string(data)
	}
	if strings.Contains(content, mavenRcMarkerStart) {
		return nil
	}

	block := buildMavenRcBlock(desiredMavenOptsTokens())
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += block

	return os.WriteFile(mavenrcPath, []byte(content), 0644)
}

func uninstallMavenOptsOverride(_ context.Context, homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")
	data, err := os.ReadFile(mavenrcPath)
	if err != nil {
		return nil
	}

	newContent, removed, err := removeAikidoBlock(string(data), mavenRcMarkerStart, mavenRcMarkerEnd)
	if err != nil {
		return err
	}
	if !removed {
		return nil
	}

	return os.WriteFile(mavenrcPath, []byte(newContent), 0644)
}

func buildMavenRcBlock(tokens []string) string {
	joined := strings.Join(tokens, " ")
	return fmt.Sprintf(`%s
export MAVEN_OPTS="$MAVEN_OPTS %s"
%s
`, mavenRcMarkerStart, joined, mavenRcMarkerEnd)
}
