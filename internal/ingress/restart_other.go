//go:build !darwin

package ingress

import (
	"context"
	"fmt"
)

func requestSystemRestart(_ context.Context) error {
	return fmt.Errorf("system restart is only supported on macOS")
}
