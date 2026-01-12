package service

import (
	"context"
	"time"

	"github.com/Cypher012/userauth/pkg/auth/domain"
	"github.com/Cypher012/userauth/pkg/auth/ports"
)

// TokenService handles email token operations.
type TokenService struct {
	repo      ports.EmailTokenRepository
	generator ports.TokenGenerator
	ttl       time.Duration
}

// NewTokenService creates a new TokenService.
func NewTokenService(
	repo ports.EmailTokenRepository,
	generator ports.TokenGenerator,
	ttl time.Duration,
) *TokenService {
	return &TokenService{
		repo:      repo,
		generator: generator,
		ttl:       ttl,
	}
}

// CreateToken generates a new token for the given user and type.
// Returns the raw token (to be sent to user) - only the hash is stored.
func (s *TokenService) CreateToken(ctx context.Context, userID string, tokenType domain.TokenType) (string, error) {
	rawToken, err := s.generator.Generate()
	if err != nil {
		return "", err
	}

	hash := s.generator.Hash(rawToken)
	expiresAt := time.Now().Add(s.ttl)

	err = s.repo.Create(ctx, domain.EmailTokenCreate{
		UserID:    userID,
		TokenHash: hash,
		Type:      tokenType,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return "", err
	}

	return rawToken, nil
}

// VerifyToken validates a token and returns the user ID.
// The token is marked as used after successful verification.
func (s *TokenService) VerifyToken(ctx context.Context, rawToken string, tokenType domain.TokenType) (string, error) {
	hash := s.generator.Hash(rawToken)

	token, err := s.repo.GetValidToken(ctx, hash, tokenType)
	if err != nil {
		return "", err
	}

	if err := s.repo.MarkUsed(ctx, token.ID); err != nil {
		return "", err
	}

	return token.UserID, nil
}
