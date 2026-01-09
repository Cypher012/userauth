package token

import (
	"context"
	"time"

	"github.com/Cypher012/userauth/internal/security"
)

type TokenService struct {
	repo               *TokenRepo
	email_token_secret string
}

func NewTokenService(repo *TokenRepo, email_token_secret string) *TokenService {
	return &TokenService{
		repo:               repo,
		email_token_secret: email_token_secret,
	}
}

func (s *TokenService) CreateVerificationEmailToken(ctx context.Context, userId, email string) (rawToken string, err error) {
	rawToken, err = security.GenerateToken()
	if err != nil {
		return "", err
	}

	hash := security.HashTokenKey(rawToken, s.email_token_secret)

	expires := time.Now().Add(1 * time.Hour)
	if err := s.repo.Create(ctx, userId, hash, VerifyEmailTokenType, expires); err != nil {
		return "", err
	}

	return rawToken, nil
}

func (s *TokenService) VerifyEmailToken(ctx context.Context, rawToken string) error {
	hash := security.HashTokenKey(rawToken, s.email_token_secret)
	token, err := s.repo.GetValidEmailToken(ctx, hash, VerifyEmailTokenType)
	if err != nil {
		return err
	}

	if err := s.repo.MarkEmailTokenUsed(ctx, token.ID.String()); err != nil {
		return err
	}

	return nil
}
