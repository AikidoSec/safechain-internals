//go:build darwin

package platform

import (
	"os"
	"path/filepath"
)

const (
	mavenRcMarkerStart = "# aikido-safe-chain-start"
	mavenRcMarkerEnd   = "# aikido-safe-chain-end"
	mavenRcFilePerm    = 0o644
	mavenRcFilename    = ".mavenrc"
	mavenRcLine        = `export MAVEN_OPTS="$MAVEN_OPTS -Daikido.safechain.mavenopts=true -Djavax.net.ssl.trustStoreType=KeychainStore -Djavax.net.ssl.trustStore=NONE"`
)

func InstallMavenOptsOverride(homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, mavenRcFilename)
	return installMavenRcOverride(mavenrcPath,
		mavenRcMarkerStart,
		mavenRcMarkerEnd,
		mavenRcLine,
		mavenRcFilePerm,
	)
}

func UninstallMavenOptsOverride(homeDir string) error {
	mavenrcPath := filepath.Join(homeDir, mavenRcFilename)
	return uninstallMavenRcOverride(mavenrcPath,
		mavenRcMarkerStart,
		mavenRcMarkerEnd,
		mavenRcFilePerm,
	)
}

func GetMavenHomeDir() (string, error) {
	if config.HomeDir != "" {
		return config.HomeDir, nil
	}
	return os.UserHomeDir()
}
