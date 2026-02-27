package ingress

import (
	"net/http"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/uiconfig"
)

// validateUIToken checks Authorization: Bearer <token> against the shared UI token.
// If invalid, it writes 401 and returns false.
func validateUIToken(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token != uiconfig.Token() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
