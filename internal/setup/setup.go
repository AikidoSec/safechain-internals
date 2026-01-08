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

func Teardown(ctx context.Context) error {
	runner := NewRunner(true)
	if err := runner.Run(ctx); err != nil {
		return fmt.Errorf("failed to do setup teardown: %v", err)
	}
	return nil
}
