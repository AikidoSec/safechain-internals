package shared

import (
	"fmt"
	"os"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/utils"
)

type ManagedBlockFormat struct {
	StartMarker string
	EndMarker   string
}

func BuildManagedBlock(body string, format ManagedBlockFormat, newline string) string {
	return format.StartMarker + newline + body + newline + format.EndMarker + newline
}

func DetectNewline(content string) string {
	if strings.Contains(content, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

func HasTrailingNewline(content string) bool {
	return strings.HasSuffix(content, "\n") || strings.HasSuffix(content, "\r\n")
}

func WriteManagedBlock(path string, body string, perm os.FileMode, format ManagedBlockFormat) error {
	content := ""
	if data, err := os.ReadFile(path); err == nil {
		content = string(data)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	newline := DetectNewline(content)

	stripped, _, err := utils.RemoveMarkedBlock(content, format.StartMarker, format.EndMarker)
	if err != nil {
		return fmt.Errorf("failed to remove existing managed block in %s: %w", path, err)
	}

	if stripped != "" && !HasTrailingNewline(stripped) {
		stripped += newline
	}

	body = strings.ReplaceAll(body, "\r\n", "\n")
	if newline != "\n" {
		body = strings.ReplaceAll(body, "\n", newline)
	}

	return os.WriteFile(path, []byte(stripped+BuildManagedBlock(body, format, newline)), perm)
}
