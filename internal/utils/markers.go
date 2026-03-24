package utils

import (
	"fmt"
	"os"
	"strings"
)

// RemoveMarkedBlock removes the first block delimited by startMarker and endMarker.
func RemoveMarkedBlock(content, startMarker, endMarker string) (string, bool, error) {
	before, rest, found := strings.Cut(content, startMarker)
	if !found {
		return content, false, nil
	}

	_, after, found := strings.Cut(rest, endMarker)
	if !found {
		return "", false, fmt.Errorf("found start marker but not end marker - corrupt configuration")
	}

	// Trim leading newlines from the remaining content to avoid leaving blank lines after removal.
	after = strings.TrimLeft(after, "\r\n")
	return before + after, true, nil
}

// RemoveManagedBlock removes the first marker-delimited block from a file in place.
func RemoveManagedBlock(path string, perm os.FileMode, startMarker, endMarker string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	content, removed, err := RemoveMarkedBlock(string(data), startMarker, endMarker)
	if err != nil {
		return fmt.Errorf("failed to remove managed block in %s: %w", path, err)
	}
	if !removed {
		return nil
	}

	return os.WriteFile(path, []byte(content), perm)
}
