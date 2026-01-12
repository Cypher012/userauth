package postgres

import (
	"context"
	"errors"

	sqlc "github.com/Cypher012/userauth/internal/db/sqlc"
	"github.com/Cypher012/userauth/pkg/auth/autherr"
	"github.com/Cypher012/userauth/pkg/auth/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionRepository implements ports.SessionRepository using PostgreSQL.
type SessionRepository struct {
	q *sqlc.Queries
}

// NewSessionRepository creates a new PostgreSQL session repository.
func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{
		q: sqlc.New(pool),
	}
}

// Create creates a new session.
func (r *SessionRepository) Create(ctx context.Context, data domain.SessionCreate) (domain.Session, error) {
	userUUID, err := parseUUID(data.UserID)
	if err != nil {
		return domain.Session{}, err
	}

	expiresAt, err := parseTimestamp(data.ExpiresAt)
	if err != nil {
		return domain.Session{}, err
	}

	session, err := r.q.CreateSession(ctx, sqlc.CreateSessionParams{
		UserID:           userUUID,
		RefreshTokenHash: data.RefreshTokenHash,
		DeviceName:       pgtype.Text{String: data.DeviceName, Valid: data.DeviceName != ""},
		DeviceInfo:       pgtype.Text{String: data.DeviceInfo, Valid: data.DeviceInfo != ""},
		IpAddress:        pgtype.Text{String: data.IPAddress, Valid: data.IPAddress != ""},
		ExpiresAt:        expiresAt,
	})
	if err != nil {
		return domain.Session{}, err
	}

	return sqlcSessionToDomain(session), nil
}

// GetByID retrieves a session by ID.
func (r *SessionRepository) GetByID(ctx context.Context, id string) (domain.Session, error) {
	uuid, err := parseUUID(id)
	if err != nil {
		return domain.Session{}, err
	}

	session, err := r.q.GetSessionById(ctx, uuid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Session{}, autherr.ErrSessionNotFound
		}
		return domain.Session{}, err
	}

	return sqlcSessionToDomain(session), nil
}

// GetActiveByUserID retrieves all active sessions for a user.
func (r *SessionRepository) GetActiveByUserID(ctx context.Context, userID string) ([]domain.Session, error) {
	uuid, err := parseUUID(userID)
	if err != nil {
		return nil, err
	}

	sessions, err := r.q.ListActiveUserSessions(ctx, uuid)
	if err != nil {
		return nil, err
	}

	result := make([]domain.Session, len(sessions))
	for i, s := range sessions {
		result[i] = sqlcSessionToDomain(s)
	}

	return result, nil
}

// UpdateLastUsed updates the last used timestamp.
func (r *SessionRepository) UpdateLastUsed(ctx context.Context, sessionID string) error {
	uuid, err := parseUUID(sessionID)
	if err != nil {
		return err
	}

	return r.q.UpdateSessionLastUsed(ctx, uuid)
}

// Revoke revokes a session.
func (r *SessionRepository) Revoke(ctx context.Context, sessionID string) error {
	uuid, err := parseUUID(sessionID)
	if err != nil {
		return err
	}

	return r.q.RevokeSession(ctx, uuid)
}

// RevokeAllForUser revokes all sessions for a user.
func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	uuid, err := parseUUID(userID)
	if err != nil {
		return err
	}

	return r.q.RevokeAllUserSessions(ctx, uuid)
}

// Helper functions

func parseTimestamp(t interface{ Unix() int64 }) (pgtype.Timestamp, error) {
	var ts pgtype.Timestamp
	if err := ts.Scan(t); err != nil {
		return pgtype.Timestamp{}, err
	}
	return ts, nil
}

func sqlcSessionToDomain(s sqlc.Session) domain.Session {
	session := domain.Session{
		ID:               s.ID.String(),
		UserID:           s.UserID.String(),
		RefreshTokenHash: s.RefreshTokenHash,
		DeviceName:       s.DeviceName.String,
		DeviceInfo:       s.DeviceInfo.String,
		IPAddress:        s.IpAddress.String,
		ExpiresAt:        s.ExpiresAt.Time,
		CreatedAt:        s.CreatedAt.Time,
		LastUsed:         s.LastUsed.Time,
	}

	if s.RevokedAt.Valid {
		session.RevokedAt = &s.RevokedAt.Time
	}

	return session
}
