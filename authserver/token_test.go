package authserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/andreistefanciprian/oauth_play/pkce"
)

func setupTokenRequest(t *testing.T, s *Server) (code, verifier string) {
	t.Helper()

	verifier, _ = pkce.GenerateCodeVerifier()
	challenge := pkce.GenerateCodeChallenge(verifier)
	code, _ = GenerateAuthCode()
	s.Codes.Store(code, AuthCodeEntry{
		Challenge:   challenge,
		ClientID:    "testclient",
		RedirectURI: "https://app.example.com/callback",
	})
	return code, verifier
}

func postToken(s *Server, vals url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.HandleToken(rr, req)
	return rr
}

func TestHandleToken_ValidRequest(t *testing.T) {
	s := newTestServer()
	code, verifier := setupTokenRequest(t, s)

	rr := postToken(s, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"testclient"},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp tokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected access_token in response")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("got token_type %q, want Bearer", resp.TokenType)
	}
}

func TestHandleToken_WrongVerifier(t *testing.T) {
	s := newTestServer()
	code, _ := setupTokenRequest(t, s)

	rr := postToken(s, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {"wrongverifier"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"testclient"},
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleToken_CodeReuse(t *testing.T) {
	s := newTestServer()
	code, verifier := setupTokenRequest(t, s)

	vals := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"testclient"},
	}

	postToken(s, vals)
	rr := postToken(s, vals)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("second use of same code should fail, got %d", rr.Code)
	}
}

func TestHandleToken_RedirectURIMismatch(t *testing.T) {
	s := newTestServer()
	code, verifier := setupTokenRequest(t, s)

	rr := postToken(s, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {"https://evil.com/callback"},
		"client_id":     {"testclient"},
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleToken_ClientIDMismatch(t *testing.T) {
	s := newTestServer()
	code, verifier := setupTokenRequest(t, s)

	rr := postToken(s, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"wrongclient"},
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleToken_UnsupportedGrantType(t *testing.T) {
	s := newTestServer()

	rr := postToken(s, url.Values{
		"grant_type": {"client_credentials"},
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}
