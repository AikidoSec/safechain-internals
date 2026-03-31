package docker

import "strings"

// debianFamilyIDs lists well-known Debian-family OS IDs as they appear in
// /etc/os-release. ID_LIKE matching catches derivatives not listed here.
var debianFamilyIDs = map[string]struct{}{
	"debian":    {},
	"ubuntu":    {},
	"linuxmint": {},
	"pop":       {},
	"kali":      {},
}

// rhelFamilyIDs lists well-known RHEL-family OS IDs as they appear in
// /etc/os-release. ID_LIKE matching catches derivatives not listed here.
var rhelFamilyIDs = map[string]struct{}{
	"rhel":      {},
	"centos":    {},
	"fedora":    {},
	"amzn":      {},
	"rocky":     {},
	"almalinux": {},
	"ol":        {},
}

// parseOSRelease parses the contents of /etc/os-release into a key→value map.
// Quoted values have their surrounding double-quotes stripped. Comment lines
// and malformed lines (no "=" separator) are ignored.
func parseOSRelease(contents string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		values[key] = strings.Trim(value, `"`)
	}
	return values
}

func isAlpine(id string) bool {
	return id == "alpine"
}

func isDebianFamily(id, idLike string) bool {
	if _, ok := debianFamilyIDs[id]; ok {
		return true
	}
	return strings.Contains(idLike, "debian") || strings.Contains(idLike, "ubuntu")
}

func isRHELFamily(id, idLike string) bool {
	if _, ok := rhelFamilyIDs[id]; ok {
		return true
	}
	return strings.Contains(idLike, "rhel") || strings.Contains(idLike, "fedora") || strings.Contains(idLike, "centos")
}
