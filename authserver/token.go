package authserver

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/andreistefanciprian/oauth_play/pkce"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// HandleToken handles POST /token.
// It validates the auth code, verifies the PKCE challenge, and issues tokens.
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")

	if grantType != "authorization_code" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}

	if code == "" || verifier == "" || redirectURI == "" || clientID == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}

	entry, err := s.Codes.Consume(code)
	if err != nil {
		slog.Warn("Failed to consume auth code", "error", err)
		http.Error(w, "invalid or expired auth code", http.StatusBadRequest)
		return
	}

	if entry.ClientID != clientID {
		slog.Warn("client_id mismatch", "got", clientID, "want", entry.ClientID)
		http.Error(w, "client_id mismatch", http.StatusBadRequest)
		return
	}

	if entry.RedirectURI != redirectURI {
		slog.Warn("redirect_uri mismatch", "got", redirectURI, "want", entry.RedirectURI)
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	if !pkce.VerifyCodeChallenge(verifier, entry.Challenge) {
		slog.Warn("PKCE verification failed", "client_id", clientID)
		http.Error(w, "invalid code_verifier", http.StatusBadRequest)
		return
	}

	slog.Info("PKCE verified, issuing tokens", "client_id", clientID)

	// subject would normally come from the authenticated user session;
	// using client_id as a stand-in until a login flow is wired up.
	subject := clientID

	accessToken, err := s.Tokens.IssueAccessToken(subject, clientID)
	if err != nil {
		http.Error(w, "failed to issue access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := s.Tokens.IssueRefreshToken(subject, clientID)
	if err != nil {
		http.Error(w, "failed to issue refresh token", http.StatusInternalServerError)
		return
	}

	resp := tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 minutes
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
