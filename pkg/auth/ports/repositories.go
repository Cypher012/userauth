package ports

import (
	"context"

	"github.com/Cypher012/userauth/pkg/auth/domain"
)

// UserRepository defines the interface for user persistence.
type UserRepository interface {
	// Create creates a new user and returns the created user.
	Create(ctx context.Context, data domain.UserCreate) (domain.User, error)

	// GetByID retrieves a user by their ID.
	GetByID(ctx context.Context, id string) (domain.User, error)

	// GetByEmail retrieves a user by their email address.
	GetByEmail(ctx context.Context, email string) (domain.User, error)

	// UpdatePassword updates a user's password hash.
	UpdatePassword(ctx context.Context, userID, passwordHash string) error

	// SetEmailVerified marks a user's email as verified.
	SetEmailVerified(ctx context.Context, userID string) error

	// EmailExists checks if an email address is already registered.
	EmailExists(ctx context.Context, email string) (bool, error)
}

// SessionRepository defines the interface for session persistence.
type SessionRepository interface {
	// Create creates a new session.
	Create(ctx context.Context, data domain.SessionCreate) (domain.Session, error)

	// GetByID retrieves a session by ID.
	GetByID(ctx context.Context, id string) (domain.Session, error)

	// GetActiveByUserID retrieves all active sessions for a user.
	GetActiveByUserID(ctx context.Context, userID string) ([]domain.Session, error)

	// UpdateLastUsed updates the last used timestamp.
	UpdateLastUsed(ctx context.Context, sessionID string) error

	// Revoke revokes a session.
	Revoke(ctx context.Context, sessionID string) error

	// RevokeAllForUser revokes all sessions for a user.
	RevokeAllForUser(ctx context.Context, userID string) error
}

// EmailTokenRepository defines the interface for email token persistence.
type EmailTokenRepository interface {
	// Create creates a new email token.
	Create(ctx context.Context, data domain.EmailTokenCreate) error

	// GetValidToken retrieves a valid (unused, unexpired) token by hash and type.
	GetValidToken(ctx context.Context, tokenHash string, tokenType domain.TokenType) (domain.EmailToken, error)

	// MarkUsed marks a token as used.
	MarkUsed(ctx context.Context, tokenID string) error

	// DeleteExpired removes expired tokens (for cleanup).
	DeleteExpired(ctx context.Context) error
}
