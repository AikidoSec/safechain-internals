//go:build !darwin

package logcollector

import (
	"context"
	"log"

	"github.com/AikidoSec/safechain-internals/internal/config"
)

func Collect(_ context.Context, _ *config.ConfigInfo) error {
	log.Println("Log collection is not yet implemented on this platform")
	return nil
}
