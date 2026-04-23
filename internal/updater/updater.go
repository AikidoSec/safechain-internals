package updater

import (
	"context"
	"log"
)

// TODO: Implement platform-specific update logic (pkg for macOS, msi/exe for Windows).
func UpdateTo(ctx context.Context, version string) error {
	log.Printf("Update to version %s requested but updater is not yet implemented", version)
	return nil
}
