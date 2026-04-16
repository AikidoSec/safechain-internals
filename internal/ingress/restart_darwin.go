//go:build darwin

package ingress

import (
	"context"
	"fmt"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func requestSystemRestart(ctx context.Context) error {
	script := `tell application "System Events" to restart`
	_, err := platform.RunInAuditSessionOfCurrentUser(ctx, "osascript", []string{"-e", script})
	if err != nil {
		return fmt.Errorf("failed to request system restart: %w", err)
	}
	return nil
}
