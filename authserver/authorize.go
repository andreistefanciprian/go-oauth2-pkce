package authserver

import (
	"log/slog"
	"net/http"
)

// HandleAuthorize handles GET /authorize.
// It validates the client, stores the auth code, and redirects to the client's redirect_uri.
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	state := q.Get("state")

	if clientID == "" || redirectURI == "" || challenge == "" || state == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}

	// OAuth 2.1 mandates S256; plain is not allowed.
	if method != "S256" {
		http.Error(w, "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}

	client, ok := s.lookupClient(clientID)
	if !ok {
		slog.Warn("Unknown client", "client_id", clientID)
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}

	if !s.isRedirectURIAllowed(client, redirectURI) {
		slog.Warn("Redirect URI not allowed", "client_id", clientID, "redirect_uri", redirectURI)
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	code, err := GenerateAuthCode()
	if err != nil {
		http.Error(w, "failed to generate auth code", http.StatusInternalServerError)
		return
	}

	s.Codes.Store(code, AuthCodeEntry{
		Challenge:   challenge,
		ClientID:    clientID,
		RedirectURI: redirectURI,
	})

	redirectTo := redirectURI + "?code=" + code + "&state=" + state
	slog.Info("Redirecting to client", "redirect_uri", redirectTo)
	http.Redirect(w, r, redirectTo, http.StatusFound)
}
