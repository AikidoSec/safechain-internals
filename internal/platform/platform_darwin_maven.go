//go:build darwin

package platform

import (
	"fmt"
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
	mavenRcFilePerm = 0o644
)

func InstallMavenOptsOverride(homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")

	content := ""
	if data, err := os.ReadFile(mavenrcPath); err == nil {
		content = string(data)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read .mavenrc: %w", err)
	}

	if strings.Contains(content, mavenRcMarkerStart) {
		if !strings.Contains(content, mavenRcMarkerEnd) {
			return fmt.Errorf("found start marker in .mavenrc but not end marker - corrupt configuration")
		}
		return nil
	}

	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	return os.WriteFile(mavenrcPath, []byte(content+mavenRcBlock), mavenRcFilePerm)
}

func UninstallMavenOptsOverride(homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")

	data, err := os.ReadFile(mavenrcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read .mavenrc: %w", err)
	}

	newContent, removed, err := removeMarkedBlock(string(data), mavenRcMarkerStart, mavenRcMarkerEnd)
	if err != nil {
		return err
	}
	if !removed {
		return nil
	}

	return os.WriteFile(mavenrcPath, []byte(newContent), mavenRcFilePerm)
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
