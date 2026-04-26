package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/andreistefanciprian/go-oauth2-pkce/authserver"
)

func signingKey() []byte {
	if k := os.Getenv("SIGNING_KEY"); k != "" {
		return []byte(k)
	}
	return []byte("super-secret-signing-key-change-in-prod")
}

func redirectURI() string {
	if u := os.Getenv("REDIRECT_URI"); u != "" {
		return u
	}
	return "http://localhost:9000/callback"
}

func main() {
	server := authserver.NewServer([]authserver.Client{
		{
			ID:           "myapp",
			RedirectURIs: []string{redirectURI()},
		},
	}, signingKey())

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", server.HandleAuthorize)
	mux.HandleFunc("/token", server.HandleToken)

	slog.Info("Auth server listening", "addr", ":8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("Auth server failed", "error", err)
	}
}
