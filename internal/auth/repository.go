package auth

import (
	"context"
	"errors"

	"github.com/Cypher012/userauth/internal/db/pgtypes"
	sqlc "github.com/Cypher012/userauth/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUserNotFound = errors.New("user not found")
var ErrUserAlreadyExists = errors.New("user already exists")

const pgUniqueViolation = "23505"

type AuthRepository struct {
	q *sqlc.Queries
}

func NewAuthRepository(pool *pgxpool.Pool) *AuthRepository {
	return &AuthRepository{
		q: sqlc.New(pool),
	}
}

func (r *AuthRepository) GetUserByEmail(ctx context.Context, email string) (sqlc.User, error) {
	user, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.User{}, ErrUserNotFound
		}
		return sqlc.User{}, err
	}
	return user, nil
}

func (r *AuthRepository) CreateUser(ctx context.Context, email string, passwordHash string) (sqlc.CreateUserRow, error) {
	user, err := r.q.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        email,
		PasswordHash: passwordHash,
	})

	if err != nil {
		pgError, ok := err.(*pgconn.PgError)
		if ok && pgError.Code == pgUniqueViolation {
			return sqlc.CreateUserRow{}, ErrUserAlreadyExists
		}
		return sqlc.CreateUserRow{}, err
	}

	return user, nil
}

func (r *AuthRepository) GetUserById(ctx context.Context, userId string) (sqlc.User, error) {
	userUUID, err := pgtypes.ParseUUID(userId)
	if err != nil {
		return sqlc.User{}, err
	}

	user, err := r.q.GetUserByID(ctx, *userUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.User{}, ErrUserNotFound
		}
		return sqlc.User{}, err
	}
	return user, nil
}

func (r *AuthRepository) SetUserEmailVerified(ctx context.Context, userId string) error {
	userUUID, err := pgtypes.ParseUUID(userId)
	if err != nil {
		return err
	}

	return r.q.SetUserEmailVerified(ctx, *userUUID)
}

func (r *AuthRepository) UpdateUserPassword(ctx context.Context, userId string, passwordHash string) error {
	userUUID, err := pgtypes.ParseUUID(userId)
	if err != nil {
		return err
	}

	return r.q.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		ID:           *userUUID,
		PasswordHash: passwordHash,
	})
}

func (r *AuthRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	return r.q.EmailExists(ctx, email)
}
