package proxyingress

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/AikidoSec/safechain-agent/internal/ui"
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

func showBlockedModal(event BlockEvent) {
	title := "SafeChain Ultimate - Blocked malware."

	var text string
	if event.PackageVersion != "" {
		text = fmt.Sprintf(
			"SafeChain blocked a potentially malicious %s package:\n\n%s@%s",
			event.Product,
			event.PackageName,
			event.PackageVersion,
		)
	} else {
		text = fmt.Sprintf(
			"SafeChain blocked a potentially malicious %s package:\n\n%s",
			event.Product,
			event.PackageName,
		)
	}

	if err := ui.ShowBlockedModal(text, title, nil); err != nil {
		log.Printf("Failed to show blocked modal: %v", err)
	}
}
