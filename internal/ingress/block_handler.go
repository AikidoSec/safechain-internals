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

	log.Printf("Received block event: product=%s package=%s reason=%s", event.Artifact.Product, event.Artifact.PackageName, event.BlockReason)

	// Show UI modal in a goroutine to not block the HTTP response
	go showBlockedModal(event, s.Addr())

	w.WriteHeader(http.StatusOK)
}

// showBlockedModal launches the ui binary as the current user to display the UI.
func showBlockedModal(event BlockEvent, ingressAddress string) {
	cfg := platform.GetConfig()
	binaryPath := filepath.Join(cfg.BinaryDir, platform.SafeChainUIBinaryName)

	title := buildBlockedTitle(event)
	subtitle := buildBlockedSubtitle(event)
	key := buildKey(event)

	args := []string{
		"--package-id", key,
		// Encapsulate title as an argument: It can contain spaces causing the argument parsing to fail for windows.
		"--title", fmt.Sprintf("\"%s\"", title),
		"--subtitle", fmt.Sprintf("\"%s\"", subtitle),
		"--ingress", ingressAddress,
		"--bypass-enabled=true",
		"--product", event.Artifact.Product,
		"--package-name", event.Artifact.PackageName,
		"--package-version", event.Artifact.PackageVersion,
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

// productDisplayName maps proxy product identifiers to UI display names.
func productDisplayName(product string) string {
	switch product {
	case "skills_sh":
		return "skills.sh"
	default:
		return product
	}
}

func buildBlockedTitle(event BlockEvent) string {
	return fmt.Sprintf("SafeChain blocked a %s package:", productDisplayName(event.Artifact.Product))
}

func buildBlockedSubtitle(event BlockEvent) string {
	if event.BlockReason == "request_install" {
		return "This package requires approval before it can be installed."
	}
	return "Installing this package has been blocked because it looks malicious."
}

func buildKey(event BlockEvent) string {
	if event.Artifact.PackageVersion != "" {
		return fmt.Sprintf(
			"%s@%s",
			event.Artifact.PackageName,
			event.Artifact.PackageVersion,
		)
	}
	return fmt.Sprintf(
		"%s",
		event.Artifact.PackageName,
	)
}
