package autherr

import "errors"

// Domain errors - these are returned by the auth module.
// Consumers can use errors.Is() to check for specific errors.
var (
	// User errors
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid email or password")

	// Token errors
	ErrTokenInvalid = errors.New("token is invalid")
	ErrTokenExpired = errors.New("token has expired")
	ErrTokenUsed    = errors.New("token has already been used")

	// Session errors
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionRevoked  = errors.New("session has been revoked")

	// Validation errors
	ErrEmailRequired    = errors.New("email is required")
	ErrPasswordRequired = errors.New("password is required")

	// Internal errors
	ErrPasswordHash = errors.New("password hashing failed")
	ErrInternal     = errors.New("internal error")

	// Config errors
	ErrConfigMissingJWTSecret        = errors.New("config: JWT secret is required")
	ErrConfigMissingEmailTokenSecret = errors.New("config: email token secret is required")
	ErrConfigMissingBaseURL          = errors.New("config: base URL is required")
)
