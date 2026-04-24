package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/andreistefanciprian/go-oauth2-pkce/authserver"
)

var testSigningKey = []byte("test-signing-key-not-for-production")

func newTestValidator() *authserver.TokenValidator {
	return authserver.NewTokenValidator(testSigningKey)
}

func newTestIssuer() *authserver.TokenIssuer {
	return authserver.NewTokenIssuer(testSigningKey)
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "no claims in context", http.StatusInternalServerError)
		return
	}
	w.Write([]byte(claims["sub"].(string)))
}

func TestBearerAuth_ValidToken(t *testing.T) {
	token, _ := newTestIssuer().IssueAccessToken("user123", "testclient")

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	BearerAuth(newTestValidator())(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "user123" {
		t.Errorf("got body %q, want %q", rr.Body.String(), "user123")
	}
}

func TestBearerAuth_MissingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rr := httptest.NewRecorder()

	BearerAuth(newTestValidator())(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rr.Code)
	}
}

func TestBearerAuth_MalformedHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Token sometoken")
	rr := httptest.NewRecorder()

	BearerAuth(newTestValidator())(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rr.Code)
	}
}

func TestBearerAuth_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rr := httptest.NewRecorder()

	BearerAuth(newTestValidator())(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rr.Code)
	}
}

func TestBearerAuth_WrongSigningKey(t *testing.T) {
	token, _ := newTestIssuer().IssueAccessToken("user123", "testclient")

	wrongValidator := authserver.NewTokenValidator([]byte("different-key"))
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	BearerAuth(wrongValidator)(http.HandlerFunc(okHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rr.Code)
	}
}
