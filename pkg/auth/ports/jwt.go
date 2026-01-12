package ports

import (
	"context"
	"net/http"

	"github.com/Cypher012/userauth/pkg/auth/domain"
)

// JWTProvider defines the interface for JWT operations.
type JWTProvider interface {
	// GenerateTokenPair generates an access token and refresh token pair.
	GenerateTokenPair(userID string) (accessToken, refreshToken string, err error)

	// ValidateAccessToken validates an access token and returns the claims.
	ValidateAccessToken(token string) (domain.Claims, error)

	// ValidateRefreshToken validates a refresh token and returns the claims.
	ValidateRefreshToken(token string) (domain.Claims, error)

	// ExtractClaimsFromContext extracts claims from the request context.
	// This is typically set by middleware after token validation.
	ExtractClaimsFromContext(ctx context.Context) (domain.Claims, error)

	// AccessMiddleware returns middleware that validates access tokens.
	AccessMiddleware(next http.Handler) http.Handler

	// RefreshMiddleware returns middleware that validates refresh tokens.
	RefreshMiddleware(next http.Handler) http.Handler
}

// CookieManager defines the interface for cookie operations.
type CookieManager interface {
	// SetRefreshToken sets the refresh token cookie.
	SetRefreshToken(w http.ResponseWriter, token string)

	// ClearRefreshToken clears the refresh token cookie.
	ClearRefreshToken(w http.ResponseWriter)

	// GetRefreshToken retrieves the refresh token from the request.
	GetRefreshToken(r *http.Request) (string, error)
}
