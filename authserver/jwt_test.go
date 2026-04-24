package authserver

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func decodeJSON(rr *httptest.ResponseRecorder, v any) error {
	return json.NewDecoder(rr.Body).Decode(v)
}

func TestIssueAndValidateAccessToken(t *testing.T) {
	ti := NewTokenIssuer(testSigningKey)

	token, err := ti.IssueAccessToken("user123", "testclient")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := ti.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	if claims["sub"] != "user123" {
		t.Errorf("got sub %q, want %q", claims["sub"], "user123")
	}
	if claims["client_id"] != "testclient" {
		t.Errorf("got client_id %q, want %q", claims["client_id"], "testclient")
	}
	if claims["iss"] != "oauth_play" {
		t.Errorf("got iss %q, want %q", claims["iss"], "oauth_play")
	}
}

func TestValidateAccessToken_TamperedToken(t *testing.T) {
	ti := NewTokenIssuer(testSigningKey)

	_, err := ti.ValidateAccessToken("not.a.valid.jwt")
	if err == nil {
		t.Error("expected error for tampered token")
	}
}

func TestValidateAccessToken_WrongKey(t *testing.T) {
	ti := NewTokenIssuer(testSigningKey)
	token, _ := ti.IssueAccessToken("user123", "testclient")

	otherIssuer := NewTokenIssuer([]byte("different-key"))
	_, err := otherIssuer.ValidateAccessToken(token)
	if err == nil {
		t.Error("expected error when validating with wrong signing key")
	}
}

func TestIssueRefreshToken(t *testing.T) {
	ti := NewTokenIssuer(testSigningKey)

	a, err := ti.IssueRefreshToken("user123", "testclient")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, _ := ti.IssueRefreshToken("user123", "testclient")
	if a == b {
		t.Error("two refresh tokens should be unique")
	}
}

func TestHandleToken_ReturnsRealJWT(t *testing.T) {
	s := newTestServer()
	code, verifier := setupTokenRequest(t, s)

	rr := postToken(s, map[string][]string{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"testclient"},
	})

	if rr.Code != 200 {
		t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
	}

	var resp tokenResponse
	if err := decodeJSON(rr, &resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	// Validate the JWT is real and parseable
	claims, err := s.Tokens.ValidateAccessToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("access token invalid: %v", err)
	}
	if claims["client_id"] != "testclient" {
		t.Errorf("unexpected client_id in token: %v", claims["client_id"])
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh_token in response")
	}
}
