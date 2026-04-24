package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/andreistefanciprian/oauth_play/authserver"
	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const ClaimsKey contextKey = "claims"

// BearerAuth returns an HTTP middleware that validates the JWT in the Authorization header.
// On success it stores the token claims in the request context for downstream handlers.
// On failure it returns 401 and stops the chain.
func BearerAuth(issuer *authserver.TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := extractBearerToken(r)
			if !ok {
				slog.Warn("Missing or malformed Authorization header")
				http.Error(w, "missing or malformed token", http.StatusUnauthorized)
				return
			}

			claims, err := issuer.ValidateAccessToken(token)
			if err != nil {
				slog.Warn("Invalid access token", "error", err)
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext retrieves the JWT claims stored by BearerAuth.
func ClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(ClaimsKey).(jwt.MapClaims)
	return claims, ok
}

func extractBearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if token == "" {
		return "", false
	}
	return token, true
}
