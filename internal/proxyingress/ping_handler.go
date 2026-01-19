package proxyingress

import (
	"log"
	"net/http"
)

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("pong"))
	if err != nil {
		log.Printf("proxy ingress, failed to write response: %v", err)
	}
}
