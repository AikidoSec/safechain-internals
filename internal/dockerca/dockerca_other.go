//go:build !darwin && !windows

package dockerca

import (
	"context"
	"os/exec"
)

func findDockerBinary() (string, error) {
	return exec.LookPath("docker")
}

func watchContainerStarts(_ context.Context, _ string) error {
	return nil
}
