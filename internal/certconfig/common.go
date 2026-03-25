package certconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/utils"
)

type managedBlockFormat struct {
	startMarker string
	endMarker   string
}

func buildManagedBlock(body string, format managedBlockFormat, newline string) string {
	return format.startMarker + newline + body + newline + format.endMarker + newline
}

func detectNewline(content string) string {
	if strings.Contains(content, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

func hasTrailingNewline(content string) bool {
	return strings.HasSuffix(content, "\n") || strings.HasSuffix(content, "\r\n")
}

func writeManagedBlock(path string, body string, perm os.FileMode, format managedBlockFormat) error {
	content := ""
	if data, err := os.ReadFile(path); err == nil {
		content = string(data)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	newline := detectNewline(content)

	stripped, _, err := utils.RemoveMarkedBlock(content, format.startMarker, format.endMarker)
	if err != nil {
		return fmt.Errorf("failed to remove existing managed block in %s: %w", path, err)
	}

	if stripped != "" && !hasTrailingNewline(stripped) {
		stripped += newline
	}

	body = strings.ReplaceAll(body, "\r\n", "\n")
	if newline != "\n" {
		body = strings.ReplaceAll(body, "\n", newline)
	}

	return os.WriteFile(path, []byte(stripped+buildManagedBlock(body, format, newline)), perm)
}
