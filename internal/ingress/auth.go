package ingress

import (
	"net/http"
	"strings"
)

// validateUIToken authenticates requests from the UI tray app using a shared token.
// Returns false and sends 401 if authentication fails.
func (s *Server) validateUIToken(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token != s.ui.Token() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
