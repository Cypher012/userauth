package session

import (
	"context"
	"errors"
	"time"

	"github.com/Cypher012/userauth/internal/db/pgtypes"
	sqlc "github.com/Cypher012/userauth/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrSessionNotFound = errors.New("session not found")

type SessionRepository struct {
	q *sqlc.Queries
}

func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{
		q: sqlc.New(pool),
	}
}

func (r *SessionRepository) GetSessionById(ctx context.Context, sessionId string) (sqlc.Session, error) {
	sessionUUID, err := pgtypes.ParseUUID(sessionId)
	if err != nil {
		return sqlc.Session{}, err
	}

	session, err := r.q.GetSessionById(ctx, *sessionUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.Session{}, ErrSessionNotFound
		}
		return sqlc.Session{}, err
	}
	return session, nil
}

func (r *SessionRepository) CreateSession(ctx context.Context, userId string, refreshTokenHash string, deviceName string, deviceInfo string, ipAddress string, expiresAt time.Time) (sqlc.Session, error) {
	userUUID, err := pgtypes.ParseUUID(userId)
	if err != nil {
		return sqlc.Session{}, err
	}

	session, err := r.q.CreateSession(ctx, sqlc.CreateSessionParams{
		UserID:           *userUUID,
		RefreshTokenHash: refreshTokenHash,
		DeviceName:       pgtype.Text{String: deviceName, Valid: deviceName != ""},
		DeviceInfo:       pgtype.Text{String: deviceInfo, Valid: deviceInfo != ""},
		IpAddress:        pgtype.Text{String: ipAddress, Valid: ipAddress != ""},
		ExpiresAt:        pgtype.Timestamp{Time: expiresAt, Valid: true},
	})
	if err != nil {
		return sqlc.Session{}, err
	}

	return session, nil
}

func (r *SessionRepository) ListActiveUserSessions(ctx context.Context, userId string) ([]sqlc.Session, error) {
	userUUID, err := pgtypes.ParseUUID(userId)
	if err != nil {
		return nil, err
	}

	sessions, err := r.q.ListActiveUserSessions(ctx, *userUUID)
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r *SessionRepository) RevokeSession(ctx context.Context, sessionId string) error {
	sessionUUID, err := pgtypes.ParseUUID(sessionId)
	if err != nil {
		return err
	}

	return r.q.RevokeSession(ctx, *sessionUUID)
}

func (r *SessionRepository) GetSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (sqlc.Session, error) {
	session, err := r.q.GetSessionByRefreshToken(ctx, refreshTokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.Session{}, ErrSessionNotFound
		}
		return sqlc.Session{}, err
	}
	return session, nil
}

func (r *SessionRepository) UpdateSessionLastUsed(ctx context.Context, sessionId string) error {
	sessionUUID, err := pgtypes.ParseUUID(sessionId)
	if err != nil {
		return err
	}

	return r.q.UpdateSessionLastUsed(ctx, *sessionUUID)
}

func (r *SessionRepository) RotateSessionToken(ctx context.Context, sessionId string, refreshTokenHash string) error {
	sessionUUID, err := pgtypes.ParseUUID(sessionId)
	if err != nil {
		return err
	}

	return r.q.RotateSessionToken(ctx, sqlc.RotateSessionTokenParams{
		ID:               *sessionUUID,
		RefreshTokenHash: refreshTokenHash,
	})
}

func (r *SessionRepository) RevokeAllUserSessions(ctx context.Context, userId string) error {
	userUUID, err := pgtypes.ParseUUID(userId)
	if err != nil {
		return err
	}

	return r.q.RevokeAllUserSessions(ctx, *userUUID)
}

func (r *SessionRepository) RevokeAllSessions(ctx context.Context) error {
	return r.q.RevokeAllSessions(ctx)
}
