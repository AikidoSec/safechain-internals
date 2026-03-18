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

	// Docker event streaming is not used on Windows. Instead we poll bounded
	// `docker events` windows; each invocation blocks until the `--until`
	// timestamp is reached or the command fails early. To avoid missing events
	// that occur between windows, we overlap them by 1 second and deduplicate
	// container IDs.
	since := time.Now().UTC().Add(-1 * time.Second)
	previousWindowIDs := make(map[string]struct{})
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

		currentWindowIDs := make(map[string]struct{})
		for _, containerID := range splitNonEmptyLines(output) {
			if _, seen := previousWindowIDs[containerID]; seen {
				continue
			}

			currentWindowIDs[containerID] = struct{}{}
			log.Printf("Docker CA: container start event received: %s", containerID)
			if err := installCAInContainer(ctx, dockerBinary, containerID); err != nil {
				log.Printf("Docker CA: failed to update started container %s: %v", containerID, err)
			}
		}

		previousWindowIDs = currentWindowIDs
		since = until.Add(-1 * time.Second)
	}
}
