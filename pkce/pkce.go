package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
)

// GenerateCodeVerifier returns a 43-character URL-safe random string.
// RFC 7636 requires 43–128 unreserved characters; 32 random bytes → 43 base64url chars (no padding).
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	slog.Info("Generated code verifier", "verifier", base64.RawURLEncoding.EncodeToString(b))
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateCodeChallenge returns BASE64URL(SHA256(verifier)), as required by RFC 7636 §4.2.
func GenerateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	slog.Info("Generated code challenge", "challenge", challenge)
	return challenge
}

// VerifyCodeChallenge checks that SHA256(verifier) matches the stored challenge.
// Uses constant-time comparison to prevent timing attacks.
func VerifyCodeChallenge(verifier, challenge string) bool {
	expected := GenerateCodeChallenge(verifier)
	result := subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
	slog.Info("Verifying challenge", "verifier", verifier, "challenge", challenge, "match", result)
	return result
}
