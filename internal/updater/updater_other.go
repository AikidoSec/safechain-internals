//go:build !darwin

package updater

import (
	"context"
	"log"
	"runtime"
)

func platformUpdateTo(_ context.Context, version string) error {
	log.Printf("Updater: auto-update to version %s requested but not implemented for %s", version, runtime.GOOS)
	return nil
}
