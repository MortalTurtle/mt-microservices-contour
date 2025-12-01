package handlers

import (
	"encoding/json"
	"net/http"
)

func SecurePing(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "secure pong:)",
	})
}
