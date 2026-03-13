//go:build windows

package dockerca

import "os/exec"

func findDockerBinary() (string, error) {
	return exec.LookPath("docker")
}
