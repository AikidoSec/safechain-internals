package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/utils"
)

func installMavenRcOverride(mavenrcPath, startMarker, endMarker, contentLine string, filePerm os.FileMode) error {
	filename := filepath.Base(mavenrcPath)

	content := ""
	if data, err := os.ReadFile(mavenrcPath); err == nil {
		content = string(data)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", filename, err)
	}

	if strings.Contains(content, startMarker) {
		if !strings.Contains(content, endMarker) {
			return fmt.Errorf("found start marker in %s but not end marker - corrupt configuration", filename)
		}
		return nil
	}

	lineEnding := "\n"
	if strings.Contains(content, "\r\n") {
		lineEnding = "\r\n"
	}

	if content != "" && !strings.HasSuffix(content, "\n") && !strings.HasSuffix(content, "\r\n") {
		content += lineEnding
	}

	block := strings.Join([]string{startMarker, contentLine, endMarker}, lineEnding) + lineEnding
	return os.WriteFile(mavenrcPath, []byte(content+block), filePerm)
}

func uninstallMavenRcOverride(mavenrcPath, startMarker, endMarker string, filePerm os.FileMode) error {
	filename := filepath.Base(mavenrcPath)

	data, err := os.ReadFile(mavenrcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", filename, err)
	}

	newContent, removed, err := utils.RemoveMarkedBlock(string(data), startMarker, endMarker)
	if err != nil {
		return err
	}
	if !removed {
		return nil
	}

	return os.WriteFile(mavenrcPath, []byte(newContent), filePerm)
}
