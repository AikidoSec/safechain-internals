package ingress

import (
	"net/http"
	"strings"
)

// validateUIToken checks Authorization: Bearer <token> against the shared UI token.
// If invalid, it writes 401 and returns false.
func (s *Server) validateUIToken(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token != s.ui.Token() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
