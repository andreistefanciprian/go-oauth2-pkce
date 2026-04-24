package authserver

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const accessTokenTTL = 15 * time.Minute

// TokenValidator verifies JWT signatures. Used by the resource server — no issuing capability.
type TokenValidator struct {
	signingKey []byte
}

func NewTokenValidator(signingKey []byte) *TokenValidator {
	return &TokenValidator{signingKey: signingKey}
}

// ValidateAccessToken parses and verifies a signed JWT, returning its claims.
func (tv *TokenValidator) ValidateAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return tv.signingKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	slog.Info("Validated access token", "subject", claims["sub"])
	return claims, nil
}

// TokenIssuer signs and issues tokens. Used by the auth server only.
type TokenIssuer struct {
	signingKey []byte

	mu            sync.Mutex
	refreshTokens map[string]refreshEntry // in prod: replace with Redis/DB
}

type refreshEntry struct {
	ClientID string
	Subject  string
	Expiry   time.Time
}

func NewTokenIssuer(signingKey []byte) *TokenIssuer {
	return &TokenIssuer{
		signingKey:    signingKey,
		refreshTokens: make(map[string]refreshEntry),
	}
}

// IssueAccessToken returns a signed JWT access token valid for 15 minutes.
func (ti *TokenIssuer) IssueAccessToken(subject, clientID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       subject,
		"client_id": clientID,
		"iss":       "oauth_play",
		"iat":       now.Unix(),
		"exp":       now.Add(accessTokenTTL).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(ti.signingKey)
	if err != nil {
		return "", err
	}
	slog.Info("Issued access token", "subject", subject, "client_id", clientID, "exp", now.Add(accessTokenTTL))
	return signed, nil
}

// IssueRefreshToken returns an opaque random token stored server-side.
func (ti *TokenIssuer) IssueRefreshToken(subject, clientID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	ti.mu.Lock()
	ti.refreshTokens[token] = refreshEntry{
		ClientID: clientID,
		Subject:  subject,
		Expiry:   time.Now().Add(30 * 24 * time.Hour),
	}
	ti.mu.Unlock()

	slog.Info("Issued refresh token", "subject", subject, "client_id", clientID)
	return token, nil
}
