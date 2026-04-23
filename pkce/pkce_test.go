package pkce

import (
	"regexp"
	"testing"
)

var unreservedChars = regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)

func TestGenerateCodeVerifier(t *testing.T) {
	v, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// RFC 7636 §4.1: length must be 43–128
	if len(v) < 43 || len(v) > 128 {
		t.Errorf("length %d out of range [43, 128]", len(v))
	}

	// RFC 7636 §4.1: only unreserved characters
	if !unreservedChars.MatchString(v) {
		t.Errorf("verifier contains invalid characters: %q", v)
	}
}

func TestGenerateCodeVerifierIsUnique(t *testing.T) {
	a, _ := GenerateCodeVerifier()
	b, _ := GenerateCodeVerifier()
	if a == b {
		t.Error("two calls returned identical verifiers")
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	// Known vector: SHA256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656b7d08c
	// BASE64URL of those 32 bytes = ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0
	const verifier = "abc"
	const want = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"

	if got := GenerateCodeChallenge(verifier); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCodeChallengeIsDeterministic(t *testing.T) {
	v, _ := GenerateCodeVerifier()
	if GenerateCodeChallenge(v) != GenerateCodeChallenge(v) {
		t.Error("same verifier produced different challenges")
	}
}

func TestVerifyCodeChallenge(t *testing.T) {
	v, _ := GenerateCodeVerifier()
	c := GenerateCodeChallenge(v)

	if !VerifyCodeChallenge(v, c) {
		t.Error("valid verifier/challenge pair rejected")
	}
	if VerifyCodeChallenge("tampered", c) {
		t.Error("wrong verifier accepted")
	}
	if VerifyCodeChallenge(v, "tampered") {
		t.Error("wrong challenge accepted")
	}
}
