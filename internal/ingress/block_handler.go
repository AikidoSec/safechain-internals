package ingress

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/AikidoSec/safechain-agent/internal/platform"
)

const (
	BlockedModalBinaryName = "safechain-agent-ui"
)

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	var event BlockEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received block event: product=%s package=%s", event.Product, event.PackageName)

	// Show UI modal in a goroutine to not block the HTTP response
	go showBlockedModal(event)

	w.WriteHeader(http.StatusOK)
}

// showBlockedModal launches the ui binary as the current user to display the UI.
func showBlockedModal(event BlockEvent) {
	cfg := platform.GetConfig()
	binaryPath := filepath.Join(cfg.BinaryDir, BlockedModalBinaryName)

	args := []string{
		"--product", event.Product,
		"--package", event.PackageName,
	}

	if event.PackageVersion != "" {
		args = append(args, "--version", event.PackageVersion)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := platform.RunAsCurrentUser(ctx, binaryPath, args); err != nil {
		log.Printf("Failed to show blocked modal: %v", err)
	}
}
