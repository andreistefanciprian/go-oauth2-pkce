package authserver

import (
	"testing"
	"time"
)

func TestGenerateAuthCode(t *testing.T) {
	code, err := GenerateAuthCode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(code) < 43 {
		t.Errorf("auth code too short: %d chars", len(code))
	}
}

func TestGenerateAuthCodeIsUnique(t *testing.T) {
	a, _ := GenerateAuthCode()
	b, _ := GenerateAuthCode()
	if a == b {
		t.Error("two calls returned identical auth codes")
	}
}

func TestConsumeValidCode(t *testing.T) {
	store := NewAuthCodeStore()
	code, _ := GenerateAuthCode()
	store.Store(code, AuthCodeEntry{
		Challenge:   "somechallenge",
		ClientID:    "client123",
		RedirectURI: "https://app.example.com/callback",
	})

	entry, err := store.Consume(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.ClientID != "client123" {
		t.Errorf("got client_id %q, want %q", entry.ClientID, "client123")
	}
}

func TestConsumeSingleUse(t *testing.T) {
	store := NewAuthCodeStore()
	code, _ := GenerateAuthCode()
	store.Store(code, AuthCodeEntry{ClientID: "client123"})

	store.Consume(code)
	_, err := store.Consume(code)
	if err == nil {
		t.Error("second consume should have failed")
	}
}

func TestConsumeInvalidCode(t *testing.T) {
	store := NewAuthCodeStore()
	_, err := store.Consume("doesnotexist")
	if err == nil {
		t.Error("expected error for unknown code")
	}
}

func TestConsumeExpiredCode(t *testing.T) {
	store := NewAuthCodeStore()
	code, _ := GenerateAuthCode()

	entry := AuthCodeEntry{ClientID: "client123"}
	entry.Expiry = time.Now().Add(-1 * time.Second) // already expired
	store.mu.Lock()
	store.codes[code] = entry
	store.mu.Unlock()

	_, err := store.Consume(code)
	if err == nil {
		t.Error("expected error for expired code")
	}
}
