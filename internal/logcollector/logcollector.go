package logcollector

import (
	"context"
	"log"

	"github.com/AikidoSec/safechain-internals/internal/config"
)

// TODO: Implement log collection — tar+gzip the daemon/proxy/UI log files and
// POST them to the LogUploadEndpoint.
func Upload(ctx context.Context, config *config.ConfigInfo) error {
	log.Println("Log collection requested but upload is not yet implemented")
	return nil
}
