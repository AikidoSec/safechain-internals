//go:build darwin

package docker

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

	cmd, stdout, stderr, err := startDockerEventsWatcher(ctx, dockerBinary)
	if err != nil {
		return err
	}

	stderrDone := captureDockerWatcherStderr(stderr)
	if err := processDockerEventStream(ctx, dockerBinary, stdout); err != nil {
		return err
	}

	return waitForDockerEventsWatcher(ctx, cmd, stderrDone)
}

func startDockerEventsWatcher(ctx context.Context, dockerBinary string) (*exec.Cmd, io.ReadCloser, io.ReadCloser, error) {
	cmd, err := platform.CommandAsCurrentUserWithPathEnv(ctx, dockerBinary,
		"events",
		"--filter", "type=container",
		"--filter", "event=start",
		"--format", "{{.Actor.ID}}",
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build docker events watcher: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("docker events stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("docker events stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, nil, fmt.Errorf("start docker events watcher: %w", err)
	}

	return cmd, stdout, stderr, nil
}

func captureDockerWatcherStderr(stderr io.Reader) <-chan string {
	stderrDone := make(chan string, 1)
	go func() {
		// Cap stderr capture to 4 KiB; enough for docker events failures without unbounded growth.
		b, err := io.ReadAll(io.LimitReader(stderr, 4096))
		if err != nil {
			log.Printf("Docker CA: error reading docker events stderr: %v", err)
		}
		stderrDone <- strings.TrimSpace(string(b))
	}()
	return stderrDone
}

func processDockerEventStream(ctx context.Context, dockerBinary string, stdout io.Reader) error {
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

	return nil
}

func waitForDockerEventsWatcher(ctx context.Context, cmd *exec.Cmd, stderrDone <-chan string) error {
	err := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err == nil {
		return nil
	}

	errOutput := <-stderrDone
	if errOutput != "" {
		return fmt.Errorf("docker events watcher failed: %w: %s", err, errOutput)
	}

	return fmt.Errorf("docker events watcher failed: %w", err)
}
