//go:build !darwin

package logcollector

import (
	"context"
	"fmt"
)

func prepareLogs(_ context.Context) (string, error) {
	return "", fmt.Errorf("log preparation is not implemented on this platform")
}

func cleanupPreparedLogs(_ string) {}
