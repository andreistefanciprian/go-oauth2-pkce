package main

import (
	"log/slog"
	"net/http"

	"github.com/andreistefanciprian/oauth_play/authserver"
)

var signingKey = []byte("super-secret-signing-key-change-in-prod")

func main() {
	server := authserver.NewServer([]authserver.Client{
		{
			ID:           "myapp",
			RedirectURIs: []string{"http://localhost:9000/callback"},
		},
	}, signingKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", server.HandleAuthorize)
	mux.HandleFunc("/token", server.HandleToken)

	slog.Info("Auth server listening", "addr", ":8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("Auth server failed", "error", err)
	}
}
