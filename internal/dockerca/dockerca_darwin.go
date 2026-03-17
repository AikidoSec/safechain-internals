//go:build darwin

package dockerca

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

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

func watchContainerStarts(ctx context.Context, dockerBinary string) error {
	log.Println("Docker CA: event watcher started")

	cmd, err := platform.CommandAsCurrentUserWithPathEnv(ctx, dockerBinary,
		"events",
		"--filter", "type=container",
		"--filter", "event=start",
		"--format", "{{.Actor.ID}}",
	)
	if err != nil {
		return fmt.Errorf("build docker events watcher: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("docker events stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("docker events stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start docker events watcher: %w", err)
	}

	stderrDone := make(chan string, 1)
	go func() {
		// Cap stderr capture to 4 KiB; enough for docker events failures without unbounded growth.
		b, err := io.ReadAll(io.LimitReader(stderr, 4096))
		if err != nil {
			log.Printf("Docker CA: error reading docker events stderr: %v", err)
		}
		stderrDone <- strings.TrimSpace(string(b))
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		containerID := strings.TrimSpace(scanner.Text())
		if containerID == "" {
			continue
		}

		log.Printf("Docker CA: container start event received: %s", containerID)
		if err := installCAInContainer(ctx, dockerBinary, containerID); err != nil {
			log.Printf("Docker CA: failed to update started container %s: %v", containerID, err)
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("read docker events: %w", err)
	}

	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		errOutput := <-stderrDone
		if errOutput != "" {
			return fmt.Errorf("docker events watcher failed: %w: %s", err, errOutput)
		}
		return fmt.Errorf("docker events watcher failed: %w", err)
	}

	return nil
}
