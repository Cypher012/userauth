package postgres

import (
	"context"
	"errors"

	sqlc "github.com/Cypher012/userauth/internal/db/sqlc"
	"github.com/Cypher012/userauth/pkg/auth/autherr"
	"github.com/Cypher012/userauth/pkg/auth/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pgUniqueViolation = "23505"

// UserRepository implements ports.UserRepository using PostgreSQL.
type UserRepository struct {
	q *sqlc.Queries
}

// NewUserRepository creates a new PostgreSQL user repository.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{
		q: sqlc.New(pool),
	}
}

// Create creates a new user.
func (r *UserRepository) Create(ctx context.Context, data domain.UserCreate) (domain.User, error) {
	row, err := r.q.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        data.Email,
		PasswordHash: data.PasswordHash,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return domain.User{}, autherr.ErrUserAlreadyExists
		}
		return domain.User{}, err
	}

	return domain.User{
		ID:         row.ID.String(),
		Email:      row.Email,
		IsVerified: row.IsVerified,
		IsActive:   row.IsActive,
		CreatedAt:  row.CreatedAt.Time,
	}, nil
}

// GetByID retrieves a user by ID.
func (r *UserRepository) GetByID(ctx context.Context, id string) (domain.User, error) {
	uuid, err := parseUUID(id)
	if err != nil {
		return domain.User{}, err
	}

	user, err := r.q.GetUserByID(ctx, uuid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, autherr.ErrUserNotFound
		}
		return domain.User{}, err
	}

	return sqlcUserToDomain(user), nil
}

// GetByEmail retrieves a user by email.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	user, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, autherr.ErrUserNotFound
		}
		return domain.User{}, err
	}

	return sqlcUserToDomain(user), nil
}

// UpdatePassword updates a user's password hash.
func (r *UserRepository) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	uuid, err := parseUUID(userID)
	if err != nil {
		return err
	}

	return r.q.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		ID:           uuid,
		PasswordHash: passwordHash,
	})
}

// SetEmailVerified marks a user's email as verified.
func (r *UserRepository) SetEmailVerified(ctx context.Context, userID string) error {
	uuid, err := parseUUID(userID)
	if err != nil {
		return err
	}

	return r.q.SetUserEmailVerified(ctx, uuid)
}

// EmailExists checks if an email is registered.
func (r *UserRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	return r.q.EmailExists(ctx, email)
}

// Helper functions

func parseUUID(id string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(id); err != nil {
		return pgtype.UUID{}, err
	}
	return u, nil
}

func sqlcUserToDomain(u sqlc.User) domain.User {
	return domain.User{
		ID:           u.ID.String(),
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		IsVerified:   u.IsVerified,
		IsActive:     u.IsActive,
		CreatedAt:    u.CreatedAt.Time,
		UpdatedAt:    u.UpdatedAt.Time,
	}
}
