package postgres

import (
	"context"
	"errors"

	sqlc "github.com/Cypher012/userauth/internal/db/sqlc"
	"github.com/Cypher012/userauth/pkg/auth/autherr"
	"github.com/Cypher012/userauth/pkg/auth/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EmailTokenRepository implements ports.EmailTokenRepository using PostgreSQL.
type EmailTokenRepository struct {
	q *sqlc.Queries
}

// NewEmailTokenRepository creates a new PostgreSQL email token repository.
func NewEmailTokenRepository(pool *pgxpool.Pool) *EmailTokenRepository {
	return &EmailTokenRepository{
		q: sqlc.New(pool),
	}
}

// Create creates a new email token.
func (r *EmailTokenRepository) Create(ctx context.Context, data domain.EmailTokenCreate) error {
	userUUID, err := parseUUID(data.UserID)
	if err != nil {
		return err
	}

	expiresAt, err := parseTimestamp(data.ExpiresAt)
	if err != nil {
		return err
	}

	return r.q.CreateEmailToken(ctx, sqlc.CreateEmailTokenParams{
		UserID:    userUUID,
		TokenHash: data.TokenHash,
		Type:      string(data.Type),
		ExpiresAt: expiresAt,
	})
}

// GetValidToken retrieves a valid token by hash and type.
func (r *EmailTokenRepository) GetValidToken(ctx context.Context, tokenHash string, tokenType domain.TokenType) (domain.EmailToken, error) {
	token, err := r.q.GetValidEmailToken(ctx, sqlc.GetValidEmailTokenParams{
		TokenHash: tokenHash,
		Type:      string(tokenType),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.EmailToken{}, autherr.ErrTokenInvalid
		}
		return domain.EmailToken{}, err
	}

	return sqlcEmailTokenToDomain(token), nil
}

// MarkUsed marks a token as used.
func (r *EmailTokenRepository) MarkUsed(ctx context.Context, tokenID string) error {
	uuid, err := parseUUID(tokenID)
	if err != nil {
		return err
	}

	return r.q.MarkEmailTokenUsed(ctx, uuid)
}

// DeleteExpired removes expired tokens.
func (r *EmailTokenRepository) DeleteExpired(ctx context.Context) error {
	// Not implemented in original schema - would need a new query
	return nil
}

func sqlcEmailTokenToDomain(t sqlc.EmailToken) domain.EmailToken {
	token := domain.EmailToken{
		ID:        t.ID.String(),
		UserID:    t.UserID.String(),
		TokenHash: t.TokenHash,
		Type:      domain.TokenType(t.Type),
		ExpiresAt: t.ExpiresAt.Time,
		CreatedAt: t.CreatedAt.Time,
	}

	if t.UsedAt.Valid {
		token.UsedAt = &t.UsedAt.Time
	}

	return token
}
