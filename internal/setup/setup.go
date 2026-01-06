package setup

import (
	"context"
	"fmt"
)

func Install(ctx context.Context) error {
	runner := NewRunner(false)
	if err := runner.Run(ctx); err != nil {
		return fmt.Errorf("failed to do setup installation: %v", err)
	}
	return nil
}

func Uninstall(ctx context.Context) error {
	runner := NewRunner(true)
	if err := runner.Run(ctx); err != nil {
		return fmt.Errorf("failed to do setup uninstallation: %v", err)
	}
	return nil
}
