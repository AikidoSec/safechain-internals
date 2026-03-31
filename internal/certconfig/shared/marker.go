package shared

import "strings"

const AikidoCertMarker = "AIKIDO_CERT="

// ExtractMarkedCertValue scans output for a line starting with AikidoCertMarker
// and returns the value after it. This tolerates arbitrary text before or after
// the marker line, which interactive shells may produce.
func ExtractMarkedCertValue(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		if strings.HasPrefix(line, AikidoCertMarker) {
			return strings.TrimSpace(line[len(AikidoCertMarker):])
		}
	}
	return ""
}
