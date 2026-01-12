package auth

import "github.com/Cypher012/userauth/pkg/auth/autherr"

// Re-export errors from autherr package for convenience.
// Consumers can import just "auth" and access all errors.
var (
	ErrUserNotFound       = autherr.ErrUserNotFound
	ErrUserAlreadyExists  = autherr.ErrUserAlreadyExists
	ErrInvalidCredentials = autherr.ErrInvalidCredentials

	ErrTokenInvalid = autherr.ErrTokenInvalid
	ErrTokenExpired = autherr.ErrTokenExpired
	ErrTokenUsed    = autherr.ErrTokenUsed

	ErrSessionNotFound = autherr.ErrSessionNotFound
	ErrSessionRevoked  = autherr.ErrSessionRevoked

	ErrEmailRequired    = autherr.ErrEmailRequired
	ErrPasswordRequired = autherr.ErrPasswordRequired

	ErrPasswordHash = autherr.ErrPasswordHash
	ErrInternal     = autherr.ErrInternal

	ErrConfigMissingJWTSecret        = autherr.ErrConfigMissingJWTSecret
	ErrConfigMissingEmailTokenSecret = autherr.ErrConfigMissingEmailTokenSecret
	ErrConfigMissingBaseURL          = autherr.ErrConfigMissingBaseURL
)
