package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"

	"github.com/andreistefanciprian/go-oauth2-pkce/authserver"
	"github.com/andreistefanciprian/go-oauth2-pkce/middleware"
)

func signingKey() []byte {
	if k := os.Getenv("SIGNING_KEY"); k != "" {
		return []byte(k)
	}
	return []byte("super-secret-signing-key-change-in-prod")
}

func main() {
	validator := authserver.NewTokenValidator(signingKey())

	mux := http.NewServeMux()
	mux.Handle("/profile", middleware.BearerAuth(validator)(http.HandlerFunc(profileHandler)))

	slog.Info("Resource server listening", "addr", ":8081")
	if err := http.ListenAndServe(":8081", mux); err != nil {
		slog.Error("Resource server failed", "error", err)
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "no claims in context", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"message": "Successfully authorized with JWT — resource is available",
		"claims":  claims,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
