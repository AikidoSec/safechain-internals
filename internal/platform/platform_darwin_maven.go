//go:build darwin

package platform

import "path/filepath"

const (
	mavenRcMarkerStart = "# aikido-safe-chain-start"
	mavenRcMarkerEnd   = "# aikido-safe-chain-end"
	mavenRcFilePerm    = 0o644
	mavenRcLine        = `export MAVEN_OPTS="$MAVEN_OPTS -Daikido.safechain.mavenopts=true -Djavax.net.ssl.trustStoreType=KeychainStore -Djavax.net.ssl.trustStore=NONE"`
)

func InstallMavenOptsOverride(homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")
	return installMavenRcOverride(mavenrcPath, mavenRcMarkerStart, mavenRcMarkerEnd, mavenRcLine, mavenRcFilePerm)
}

func UninstallMavenOptsOverride(homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")
	return uninstallMavenRcOverride(mavenrcPath, mavenRcMarkerStart, mavenRcMarkerEnd, mavenRcFilePerm)
}
