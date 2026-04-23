package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// GenerateCodeVerifier returns a 43-character URL-safe random string.
// RFC 7636 requires 43–128 unreserved characters; 32 random bytes → 43 base64url chars (no padding).
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	fmt.Printf("Generated code verifier: %s\n", base64.RawURLEncoding.EncodeToString(b))
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateCodeChallenge returns BASE64URL(SHA256(verifier)), as required by RFC 7636 §4.2.
func GenerateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// VerifyCodeChallenge checks that SHA256(verifier) matches the stored challenge.
// Uses constant-time comparison to prevent timing attacks.
func VerifyCodeChallenge(verifier, challenge string) bool {
	expected := GenerateCodeChallenge(verifier)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
}
