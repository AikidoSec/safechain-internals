//go:build windows

package platform

import "path/filepath"

const (
	mavenRcMarkerStart = "REM aikido-safe-chain-start"
	mavenRcMarkerEnd   = "REM aikido-safe-chain-end"
	mavenRcFilePerm    = 0o644
	mavenRcLine        = `set "MAVEN_OPTS=%MAVEN_OPTS% -Daikido.safechain.mavenopts=true -Djavax.net.ssl.trustStoreType=Windows-ROOT -Djavax.net.ssl.trustStore=NONE"`
)

func InstallMavenOptsOverride(homeDir string) error {
	return installMavenRcOverride(
		filepath.Join(homeDir, "mavenrc_pre.cmd"),
		mavenRcMarkerStart,
		mavenRcMarkerEnd,
		mavenRcLine,
		mavenRcFilePerm,
	)
}

func UninstallMavenOptsOverride(homeDir string) error {
	return uninstallMavenRcOverride(
		filepath.Join(homeDir, "mavenrc_pre.cmd"),
		mavenRcMarkerStart,
		mavenRcMarkerEnd,
		mavenRcFilePerm,
	)
}

func GetMavenHomeDir() (string, error) {
	return GetActiveUserHomeDir()
}
