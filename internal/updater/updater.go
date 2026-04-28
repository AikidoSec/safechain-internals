package updater

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const (
	releasesBaseURL = "https://github.com/AikidoSec/safechain-internals/releases"
	pkgAssetName    = "EndpointProtection.pkg"
)

// versionRegex enforces a strict MAJOR.MINOR.PATCH form (with an optional
// leading "v") so we never feed arbitrary strings into download URLs or shell
// commands.
var versionRegex = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// UpdateTo downloads, verifies, and installs the requested target version.
// On unsupported platforms it logs and returns nil.
func UpdateTo(ctx context.Context, version string) error {
	if !versionRegex.MatchString(version) {
		return fmt.Errorf("invalid target version %q: expected MAJOR.MINOR.PATCH", version)
	}
	return platformUpdateTo(ctx, version)
}

// releaseTag converts a version string ("1.2.23" or "v1.2.23") to the
// "vX.Y.Z" form used in GitHub release URLs.
func releaseTag(version string) string {
	version = strings.TrimSpace(version)
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}
