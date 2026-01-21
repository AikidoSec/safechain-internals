package ingress

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	var event BlockEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received block event: product=%s package=%s", event.Artifact.Product, event.Artifact)

	// Show UI modal in a goroutine to not block the HTTP response
	go showBlockedModal(event, s.Addr())

	w.WriteHeader(http.StatusOK)
}

// showBlockedModal launches the ui binary as the current user to display the UI.
func showBlockedModal(event BlockEvent, ingressAddress string) {
	cfg := platform.GetConfig()
	binaryPath := filepath.Join(cfg.BinaryDir, platform.SafeChainUIBinaryName)

	title := "SafeChain Ultimate"
	text := buildBlockedText(event)
	key := buildKey(event)

	args := []string{
		"--package-key", key,
		"--title", title,
		"--text", text,
		"--ingress", ingressAddress,
		"--bypass-enabled", "true",
	}

	// Make sure that the modals close on their own after an hour so there are no hanging
	// processes.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	_, err := platform.RunAsCurrentUser(ctx, binaryPath, args)
	if err != nil {
		log.Printf("Failed to show blocked modal: %v", err)
	}
}

func buildBlockedText(event BlockEvent) string {
	if event.Artifact.PackageVersion != "" {
		return fmt.Sprintf(
			"SafeChain blocked a potentially malicious %s package:\n\n%s@%s",
			event.Artifact.Product,
			event.Artifact.PackageName,
			event.Artifact.PackageVersion,
		)
	}
	return fmt.Sprintf(
		"SafeChain blocked a potentially malicious %s package:\n\n%s",
		event.Artifact.Product,
		event.Artifact.PackageName,
	)
}

func buildKey(event BlockEvent) string {
	if event.Artifact.PackageVersion != "" {
		return fmt.Sprintf(
			"%s{%s@%s}",
			event.Artifact.Product,
			event.Artifact.PackageName,
			event.Artifact.PackageVersion,
		)
	}
	return fmt.Sprintf(
		"%s{%s}",
		event.Artifact.Product,
		event.Artifact.PackageName,
	)
}
