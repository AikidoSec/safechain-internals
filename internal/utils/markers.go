package utils

import (
	"fmt"
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
