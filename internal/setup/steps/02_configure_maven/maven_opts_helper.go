package configure_maven

import (
	"context"
)

const aikidoMavenOptsMarkerToken = "-Daikido.safechain.mavenopts=true"

func ensureMavenOptsUsesSystemTrustStore(ctx context.Context, homeDir string) error {
	return installMavenOptsOverride(ctx, homeDir)
}

func removeMavenOptsSystemTrustStoreOverride(ctx context.Context, homeDir string) error {
	return uninstallMavenOptsOverride(ctx, homeDir)
}
