package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/andreistefanciprian/go-oauth2-pkce/pkce"
)

const (
	clientID    = "myapp"
	redirectURI = "http://localhost:9000/callback"
	authServer  = "http://localhost:8080"
	apiServer   = "http://localhost:8081"
)

// sessionStore bridges /login and /callback by holding {state → verifier}.
// The verifier is generated at /login but needed at /callback — it can't travel
// in the URL (it's a secret) so the server keeps it until the callback arrives.
// in prod: replace with Redis/DB backed sessions
type sessionStore struct {
	mu   sync.Mutex
	data map[string]string // state → verifier
}

func (s *sessionStore) save(state, verifier string) {
	s.mu.Lock()
	s.data[state] = verifier
	s.mu.Unlock()
}

// consume retrieves and deletes the verifier in one step.
// Delete-on-read means a replayed callback URL is rejected — the state
// is gone after the first use, so a second hit returns false.
func (s *sessionStore) consume(state string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	verifier, ok := s.data[state]
	if ok {
		delete(s.data, state)
	}
	return verifier, ok
}

var store = &sessionStore{data: make(map[string]string)}

// tokenStore holds {sessionID → accessToken} after a successful callback.
// The browser is given only the sessionID via a cookie — the JWT never leaves the server.
// in prod: replace with Redis/DB backed sessions
type tokenStore struct {
	mu   sync.Mutex
	data map[string]string // sessionID → accessToken
}

func (t *tokenStore) save(sessionID, accessToken string) {
	t.mu.Lock()
	t.data[sessionID] = accessToken
	t.mu.Unlock()
}

func (t *tokenStore) get(sessionID string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	token, ok := t.data[sessionID]
	return token, ok
}

var tokens = &tokenStore{data: make(map[string]string)}

// generateSessionID returns a random opaque string used as the session cookie value.
// The browser holds only this ID — the actual JWT is stored server-side in the token store.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/callback", handleCallback)

	slog.Info("Frontend listening", "addr", ":9000")
	slog.Info("Open in browser", "url", "http://localhost:9000/login")
	if err := http.ListenAndServe(":9000", mux); err != nil {
		slog.Error("Frontend failed", "error", err)
	}
}

// handleLogin is the entry point for the OAuth flow.
// It generates fresh PKCE params and state on every login attempt, stores
// {state → verifier} in the session, then redirects the browser to the
// auth server. The verifier never leaves the server — only the challenge does.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier, err := pkce.GenerateCodeVerifier()
	if err != nil {
		http.Error(w, "failed to generate verifier", http.StatusInternalServerError)
		return
	}

	// challenge = BASE64URL(SHA256(verifier)) — safe to send to the auth server
	challenge := pkce.GenerateCodeChallenge(verifier)

	// state is a random nonce that ties this callback to this login attempt (CSRF guard)
	state, err := pkce.GenerateState()
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}

	// store verifier server-side so /callback can retrieve it by state
	store.save(state, verifier)

	authorizeURL := fmt.Sprintf("%s/authorize?%s", authServer, url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}.Encode())

	slog.Info("Redirecting to auth server", "url", authorizeURL)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// handleCallback is called by the auth server redirect after the user authorises.
// It receives ?code=&state= in the URL, validates the state (CSRF check),
// exchanges the code for tokens, then uses the access token to call the API.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")

	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	// CSRF check: state must match what we stored at /login.
	// consume() also retrieves the verifier — the two values were stored together
	// so we get both in one step. If state is unknown or already used, reject.
	verifier, ok := store.consume(state)
	if !ok {
		slog.Warn("State mismatch — possible CSRF or replayed callback", "state", state)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// Exchange the auth code for tokens. The verifier proves we initiated this flow —
	// the auth server hashes it and checks it matches the challenge stored at /authorize.
	tokenResp, err := exchangeCode(code, verifier)
	if err != nil {
		slog.Error("Token exchange failed", "error", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	// Use the access token (JWT) to call the protected API.
	// The API server validates the token locally — it never calls the auth server.
	profile, err := fetchProfile(tokenResp["access_token"].(string))
	if err != nil {
		slog.Error("Profile fetch failed", "error", err)
		http.Error(w, "failed to fetch profile", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// exchangeCode calls POST /token on the auth server.
// Sending the verifier here is the PKCE proof — the auth server hashes it
// and compares it to the challenge it stored during /authorize.
func exchangeCode(code, verifier string) (map[string]any, error) {
	resp, err := http.PostForm(authServer+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	slog.Info("Token exchange successful")
	return result, nil
}

// fetchProfile calls GET /profile on the API server with a Bearer token.
// The API server validates the JWT locally via BearerAuth middleware —
// no call back to the auth server is needed.
func fetchProfile(accessToken string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, apiServer+"/profile", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	slog.Info("Profile fetch successful")
	return result, nil
}
