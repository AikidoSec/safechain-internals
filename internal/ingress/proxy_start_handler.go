package ingress

import (
	"log"
	"net/http"

	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

func (s *Server) handleProxyStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}

	ingressAddr := s.Addr()
	if ingressAddr == "" {
		http.Error(w, "ingress server not ready", http.StatusServiceUnavailable)
		return
	}

	opts := proxy.StartOptions{
		IngressAddr: ingressAddr,
		BaseURL:     s.config.GetBaseURL(),
		Token:       s.config.Token,
		DeviceID:    s.config.DeviceID,
		Passthrough: IsRebootRequired(),
	}

	if err := s.proxy.Start(r.Context(), opts); err != nil {
		log.Printf("ingress: proxy start: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
