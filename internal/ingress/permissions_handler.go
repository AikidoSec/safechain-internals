package ingress

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func (s *Server) handlePermissionsUpdated(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Println("Got permissions update from proxy")

	var perms PermissionsResponse
	if err := json.Unmarshal(raw, &perms); err != nil {
		http.Error(w, "invalid permissions response", http.StatusBadRequest)
		return
	}
	for _, e := range s.eventStore.List() {
		if e.Status != "request_pending" {
			continue
		}
		ecosystem := perms.Ecosystems[e.Artifact.Product]
		pkg := strings.ToLower(e.Artifact.PackageName)
		if sliceContainsFold(ecosystem.Exceptions.AllowedPackages, pkg) {
			s.eventStore.UpdateStatus(e.ID, "request_approved")
		} else if sliceContainsFold(ecosystem.Exceptions.RejectedPackages, pkg) {
			s.eventStore.UpdateStatus(e.ID, "request_rejected")
		}
	}
	go s.ui.NotifyPermissionsUpdated(perms)

	w.WriteHeader(http.StatusOK)
}

func sliceContainsFold(ss []string, target string) bool {
	for _, s := range ss {
		if strings.ToLower(s) == target {
			return true
		}
	}
	return false
}
