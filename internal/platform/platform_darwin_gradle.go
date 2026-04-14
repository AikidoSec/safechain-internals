//go:build darwin

package platform

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/utils"
)

const (
	gradlePropsMarkerStart = "# aikido-safe-chain-gradle-start"
	gradlePropsMarkerEnd   = "# aikido-safe-chain-gradle-end"
	gradlePropsBlock       = gradlePropsMarkerStart + "\n" +
		"systemProp.javax.net.ssl.trustStoreType=KeychainStore" + "\n" +
		"systemProp.javax.net.ssl.trustStore=NONE" + "\n" +
		gradlePropsMarkerEnd + "\n"
	gradlePropsFilePerm = 0o644
)

func InstallGradleSystemPropsOverride(homeDir string) error {
	gradleDir := filepath.Join(homeDir, ".gradle")
	if err := os.MkdirAll(gradleDir, 0o755); err != nil {
		return fmt.Errorf("failed to create .gradle directory: %w", err)
	}

	propsPath := filepath.Join(gradleDir, "gradle.properties")

	content := ""
	if data, err := os.ReadFile(propsPath); err == nil {
		content = string(data)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read gradle.properties: %w", err)
	}

	newContent, removed, err := utils.RemoveMarkedBlock(content, gradlePropsMarkerStart, gradlePropsMarkerEnd)
	if err != nil {
		return fmt.Errorf("failed to clean existing Gradle trust block: %w", err)
	}
	if removed {
		content = newContent
	}
	if content != "" && content[len(content)-1] != '\n' {
		content += "\n"
	}

	return os.WriteFile(propsPath, []byte(content+gradlePropsBlock), gradlePropsFilePerm)
}

func UninstallGradleSystemPropsOverride(homeDir string) error {
	propsPath := filepath.Join(homeDir, ".gradle", "gradle.properties")

	data, err := os.ReadFile(propsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read gradle.properties: %w", err)
	}

	newContent, removed, err := utils.RemoveMarkedBlock(string(data), gradlePropsMarkerStart, gradlePropsMarkerEnd)
	if err != nil {
		return err
	}
	if !removed {
		return nil
	}

	return os.WriteFile(propsPath, []byte(newContent), gradlePropsFilePerm)
}
