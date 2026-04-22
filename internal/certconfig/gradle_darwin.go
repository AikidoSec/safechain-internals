//go:build darwin

package certconfig

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/platform"
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

func installGradleTrust(_ context.Context) error {
	homeDir := platform.GetConfig().HomeDir
	gradleDir := filepath.Join(homeDir, ".gradle")
	if err := os.MkdirAll(gradleDir, 0o755); err != nil {
		return fmt.Errorf("failed to create .gradle directory: %w", err)
	}

	propsPath := filepath.Join(gradleDir, "gradle.properties")

	content := ""
	// Intentionally read the current user's fixed Gradle config file so we can
	// append or replace only our managed trust block.
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

var gradleManagedBlockFormat = managedBlockFormat{
	startMarker: gradlePropsMarkerStart,
	endMarker:   gradlePropsMarkerEnd,
}

func isGradleTrustManaged() bool {
	present, err := hasManagedBlock(
		filepath.Join(platform.GetConfig().HomeDir, ".gradle", "gradle.properties"),
		gradleManagedBlockFormat,
	)
	if err != nil {
		log.Printf("gradle: failed to check managed block: %v", err)
	}
	return present
}

func gradleNeedsRepair() bool {
	if isGradleTrustManaged() {
		return false
	}
	_, err := os.Stat(filepath.Join(platform.GetConfig().HomeDir, ".gradle", "gradle.properties"))
	return err == nil
}

func uninstallGradleTrust(_ context.Context) error {
	propsPath := filepath.Join(platform.GetConfig().HomeDir, ".gradle", "gradle.properties")

	// Intentionally read the current user's fixed Gradle config file so we can
	// remove only the trust block managed by Aikido.
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
