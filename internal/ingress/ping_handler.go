package ingress

import (
	"log"
	"net/http"
)

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("pong"))
	if err != nil {
		log.Printf("ingress: failed to write response: %v", err)
	}
}
