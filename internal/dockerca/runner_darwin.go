//go:build darwin

package dockerca

import "os/exec"

func findDockerBinary() (string, error) {
	candidates := []string{
		"docker",
		"/usr/local/bin/docker",
		"/opt/homebrew/bin/docker",
		"/Applications/Docker.app/Contents/Resources/bin/docker",
	}

	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate)
		if err == nil {
			return path, nil
		}
	}

	return "", exec.ErrNotFound
}
