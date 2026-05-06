package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

type setTokenBody struct {
	Token string `json:"token"`
}

func (s *Server) handleSetToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}

	var body setTokenBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Token == "" {
		http.Error(w, "token must not be empty", http.StatusBadRequest)
		return
	}

	s.config.SetToken(body.Token)
	if err := s.config.Save(); err != nil {
		log.Printf("ingress: failed to save config after setting token: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
