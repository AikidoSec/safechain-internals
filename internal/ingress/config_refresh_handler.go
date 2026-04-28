package ingress

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

var configRefreshHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

func (s *Server) handleConfigRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}

	token := s.config.Token
	if token == "" {
		http.Error(w, "no aikido token configured", http.StatusPreconditionFailed)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://mitm.ramaproxy.org/config/refresh", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to build refresh request: %v", err), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Authorization", token)

	resp, err := configRefreshHTTPClient.Do(req)
	if err != nil {
		log.Printf("ingress: config refresh: %v", err)
		http.Error(w, fmt.Sprintf("config refresh failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("ingress: config refresh: proxy returned %s", resp.Status)
		http.Error(w, fmt.Sprintf("proxy returned %s", resp.Status), resp.StatusCode)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
