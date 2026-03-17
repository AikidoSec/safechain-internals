//go:build windows

package dockerca

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const dockerEventsWindow = 20 * time.Second

func findDockerBinary() (string, error) {
	return exec.LookPath("docker")
}

func watchContainerStarts(ctx context.Context, dockerBinary string) error {
	log.Println("Docker CA: event watcher started")

	since := time.Now().UTC().Add(-1 * time.Second)
	for {
		until := time.Now().UTC().Add(dockerEventsWindow)
		output, err := platform.RunAsCurrentUserWithPathEnv(
			ctx,
			dockerBinary,
			"events",
			"--filter", "type=container",
			"--filter", "event=start",
			"--since", since.Format(time.RFC3339Nano),
			"--until", until.Format(time.RFC3339Nano),
			"--format", "{{.Actor.ID}}",
		)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return fmt.Errorf("watch docker events between %s and %s: %w", since.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano), err)
		}

		for _, containerID := range splitNonEmptyLines(output) {
			log.Printf("Docker CA: container start event received: %s", containerID)
			if err := installCAInContainer(ctx, dockerBinary, containerID); err != nil {
				log.Printf("Docker CA: failed to update started container %s: %v", containerID, err)
			}
		}

		// Keep a small overlap between windows so boundary timing does not drop events.
		since = until.Add(-1 * time.Second)
	}
}
