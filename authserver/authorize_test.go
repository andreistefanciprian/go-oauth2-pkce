package authserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

var testSigningKey = []byte("test-signing-key-not-for-production")

func newTestServer() *Server {
	return NewServer([]Client{
		{
			ID:           "testclient",
			RedirectURIs: []string{"https://app.example.com/callback"},
		},
	}, testSigningKey)
}

func TestHandleAuthorize_ValidRequest(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {"testclient"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {"somechallenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"randomstate"},
	}.Encode(), nil)
	rr := httptest.NewRecorder()

	s.HandleAuthorize(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusFound)
	}
	loc := rr.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header")
	}
	parsed, _ := url.Parse(loc)
	if parsed.Query().Get("state") != "randomstate" {
		t.Errorf("state not echoed in redirect: %s", loc)
	}
	if parsed.Query().Get("code") == "" {
		t.Error("no auth code in redirect")
	}
}

func TestHandleAuthorize_MissingParams(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	rr := httptest.NewRecorder()

	s.HandleAuthorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAuthorize_UnknownClient(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {"unknown"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {"somechallenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"randomstate"},
	}.Encode(), nil)
	rr := httptest.NewRecorder()

	s.HandleAuthorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAuthorize_DisallowedRedirectURI(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {"testclient"},
		"redirect_uri":          {"https://evil.com/callback"},
		"code_challenge":        {"somechallenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"randomstate"},
	}.Encode(), nil)
	rr := httptest.NewRecorder()

	s.HandleAuthorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAuthorize_PlainMethodRejected(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {"testclient"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {"somechallenge"},
		"code_challenge_method": {"plain"},
		"state":                 {"randomstate"},
	}.Encode(), nil)
	rr := httptest.NewRecorder()

	s.HandleAuthorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}
