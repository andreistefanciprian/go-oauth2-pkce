package authserver

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// AuthCodeEntry holds everything the auth server needs to validate a /token request.
type AuthCodeEntry struct {
	Challenge   string
	ClientID    string
	RedirectURI string
	Expiry      time.Time
}

// AuthCodeStore is an in-memory, single-use store for auth codes.
type AuthCodeStore struct {
	mu    sync.Mutex
	codes map[string]AuthCodeEntry
}

func NewAuthCodeStore() *AuthCodeStore {
	return &AuthCodeStore{codes: make(map[string]AuthCodeEntry)}
}

// GenerateAuthCode returns a random opaque token to be used as an auth code.
func GenerateAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	slog.Info("Generated auth code", "code", code)
	return code, nil
}

// Store saves an auth code with its associated entry. Codes expire after 10 minutes (RFC 6749 §4.1.2).
func (s *AuthCodeStore) Store(code string, entry AuthCodeEntry) {
	entry.Expiry = time.Now().Add(10 * time.Minute)
	s.mu.Lock()
	s.codes[code] = entry
	s.mu.Unlock()
	slog.Info("Stored auth code", "client_id", entry.ClientID, "expiry", entry.Expiry)
}

// Consume retrieves and deletes the auth code in one step, enforcing single-use and expiry.
func (s *AuthCodeStore) Consume(code string) (AuthCodeEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.codes[code]
	if !ok {
		slog.Warn("Auth code not found", "code", code)
		return AuthCodeEntry{}, errors.New("invalid auth code")
	}

	delete(s.codes, code)

	if time.Now().After(entry.Expiry) {
		slog.Warn("Auth code expired", "code", code, "expiry", entry.Expiry)
		return AuthCodeEntry{}, errors.New("auth code expired")
	}

	slog.Info("Consumed auth code", "client_id", entry.ClientID)
	return entry, nil
}
