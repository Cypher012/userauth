package ports

// PasswordHasher defines the interface for password hashing operations.
type PasswordHasher interface {
	// Hash generates a hash from a plaintext password.
	Hash(password string) (string, error)

	// Compare compares a plaintext password with a hash.
	// Returns nil if they match, error otherwise.
	Compare(hash, password string) error
}

// TokenGenerator defines the interface for generating secure random tokens.
type TokenGenerator interface {
	// Generate creates a new random token string.
	Generate() (string, error)

	// Hash creates a hash of the token for storage.
	Hash(token string) string
}

// EmailSender defines the interface for sending emails.
type EmailSender interface {
	// SendVerificationEmail sends an email verification link.
	SendVerificationEmail(to, verifyURL string) error

	// SendPasswordResetEmail sends a password reset link.
	SendPasswordResetEmail(to, resetURL string) error

	// SendWelcomeEmail sends a welcome email.
	SendWelcomeEmail(to string) error
}

// Logger defines the interface for logging.
type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
}

// DefaultLogger is a no-op logger used when none is provided.
type DefaultLogger struct{}

func (DefaultLogger) Info(msg string, args ...any)  {}
func (DefaultLogger) Error(msg string, args ...any) {}
func (DefaultLogger) Debug(msg string, args ...any) {}
