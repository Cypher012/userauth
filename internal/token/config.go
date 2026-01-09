package token

import "github.com/jackc/pgx/v5/pgxpool"

func TokenConfig(pool *pgxpool.Pool, email_token_secret string) *TokenService {
	repo := NewTokenRepo(pool)
	service := NewTokenService(repo, email_token_secret)

	return service
}
