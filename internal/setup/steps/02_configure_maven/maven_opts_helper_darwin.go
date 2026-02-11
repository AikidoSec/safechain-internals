//go:build darwin

package configure_maven

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	mavenRcMarkerStart = "# aikido-safe-chain-start"
	mavenRcMarkerEnd   = "# aikido-safe-chain-end"
	mavenRcBlock       = mavenRcMarkerStart + "\n" +
		`export MAVEN_OPTS="$MAVEN_OPTS -Daikido.safechain.mavenopts=true -Djavax.net.ssl.trustStoreType=KeychainStore -Djavax.net.ssl.trustStore=NONE"` + "\n" +
		mavenRcMarkerEnd + "\n"
)

func installMavenOptsOverride(homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")

	content := ""
	if data, err := os.ReadFile(mavenrcPath); err == nil {
		content = string(data)
	}
	if strings.Contains(content, mavenRcMarkerStart) {
		return nil
	}

	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(mavenrcPath, []byte(content+mavenRcBlock), 0644)
}

func uninstallMavenOptsOverride(homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")
	if data, err := os.ReadFile(mavenrcPath); err == nil {
		newContent, removed, err := removeMarkedBlock(string(data), mavenRcMarkerStart, mavenRcMarkerEnd)
		if !removed || err != nil {
			return err
		}
		return os.WriteFile(mavenrcPath, []byte(newContent), 0644)
	}
	return nil
}
