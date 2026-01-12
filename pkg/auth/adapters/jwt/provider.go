package jwt

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Cypher012/userauth/pkg/auth/domain"
	"github.com/go-chi/jwtauth/v5"
)

const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

// Provider implements ports.JWTProvider using go-chi/jwtauth.
type Provider struct {
	tokenAuth       *jwtauth.JWTAuth
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

// New creates a new JWT Provider.
func New(secret string, accessTTL, refreshTTL time.Duration) *Provider {
	return &Provider{
		tokenAuth:       jwtauth.New("HS256", []byte(secret), nil),
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}
}

// GenerateTokenPair generates an access token and refresh token pair.
func (p *Provider) GenerateTokenPair(userID string) (accessToken, refreshToken string, err error) {
	now := time.Now()

	// Generate access token
	accessClaims := map[string]any{
		"type":    tokenTypeAccess,
		"user_id": userID,
		"exp":     now.Add(p.accessTokenTTL).Unix(),
	}
	_, accessToken, err = p.tokenAuth.Encode(accessClaims)
	if err != nil {
		return "", "", err
	}

	// Generate refresh token
	refreshClaims := map[string]any{
		"type":    tokenTypeRefresh,
		"user_id": userID,
		"exp":     now.Add(p.refreshTokenTTL).Unix(),
	}
	_, refreshToken, err = p.tokenAuth.Encode(refreshClaims)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// ValidateAccessToken validates an access token and returns claims.
func (p *Provider) ValidateAccessToken(token string) (domain.Claims, error) {
	return p.validateToken(token, tokenTypeAccess)
}

// ValidateRefreshToken validates a refresh token and returns claims.
func (p *Provider) ValidateRefreshToken(token string) (domain.Claims, error) {
	return p.validateToken(token, tokenTypeRefresh)
}

func (p *Provider) validateToken(token, expectedType string) (domain.Claims, error) {
	jwtToken, err := p.tokenAuth.Decode(token)
	if err != nil {
		return domain.Claims{}, err
	}

	claims, err := jwtToken.AsMap(context.Background())
	if err != nil {
		return domain.Claims{}, err
	}

	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != expectedType {
		return domain.Claims{}, errors.New("invalid token type")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return domain.Claims{}, errors.New("user_id not found in claims")
	}

	return domain.Claims{
		UserID:    userID,
		TokenType: tokenType,
	}, nil
}

// ExtractClaimsFromContext extracts claims set by middleware.
func (p *Provider) ExtractClaimsFromContext(ctx context.Context) (domain.Claims, error) {
	_, rawClaims, err := jwtauth.FromContext(ctx)
	if err != nil {
		return domain.Claims{}, err
	}

	userID, ok := rawClaims["user_id"].(string)
	if !ok {
		return domain.Claims{}, errors.New("user_id not found in claims")
	}

	tokenType, _ := rawClaims["type"].(string)

	return domain.Claims{
		UserID:    userID,
		TokenType: tokenType,
	}, nil
}

// AccessMiddleware returns middleware that validates access tokens.
func (p *Provider) AccessMiddleware(next http.Handler) http.Handler {
	return p.baseMiddleware(next, tokenTypeAccess)
}

// RefreshMiddleware returns middleware that validates refresh tokens.
func (p *Provider) RefreshMiddleware(next http.Handler) http.Handler {
	return p.baseMiddleware(next, tokenTypeRefresh)
}

func (p *Provider) baseMiddleware(next http.Handler, expectedType string) http.Handler {
	verifier := jwtauth.Verifier(p.tokenAuth)
	authenticator := jwtauth.Authenticator(p.tokenAuth)

	return verifier(authenticator(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, claims, err := jwtauth.FromContext(r.Context())
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		tokenType, ok := claims["type"].(string)
		if !ok || tokenType != expectedType {
			http.Error(w, "invalid token type", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})))
}
