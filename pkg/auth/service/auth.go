package service

import (
	"context"
	"errors"
	"time"

	"github.com/Cypher012/userauth/pkg/auth/autherr"
	"github.com/Cypher012/userauth/pkg/auth/domain"
	"github.com/Cypher012/userauth/pkg/auth/ports"
)

// AuthService handles authentication business logic.
type AuthService struct {
	userRepo     ports.UserRepository
	tokenService *TokenService
	hasher       ports.PasswordHasher
	logger       ports.Logger
}

// NewAuthService creates a new AuthService.
func NewAuthService(
	userRepo ports.UserRepository,
	tokenService *TokenService,
	hasher ports.PasswordHasher,
	logger ports.Logger,
) *AuthService {
	if logger == nil {
		logger = ports.DefaultLogger{}
	}
	return &AuthService{
		userRepo:     userRepo,
		tokenService: tokenService,
		hasher:       hasher,
		logger:       logger,
	}
}

// AuthResult contains the result of a successful authentication.
type AuthResult struct {
	User  domain.User
	Token string // Raw email verification token (if applicable)
}

// RegisterUser creates a new user account.
func (s *AuthService) RegisterUser(ctx context.Context, email, password string) (AuthResult, error) {
	// Check if user already exists
	_, err := s.userRepo.GetByEmail(ctx, email)
	if err == nil {
		return AuthResult{}, autherr.ErrUserAlreadyExists
	}
	if !errors.Is(err, autherr.ErrUserNotFound) {
		s.logger.Error("failed to check existing user", "error", err)
		return AuthResult{}, err
	}

	// Hash password
	hash, err := s.hasher.Hash(password)
	if err != nil {
		s.logger.Error("failed to hash password", "error", err)
		return AuthResult{}, autherr.ErrPasswordHash
	}

	// Create user
	user, err := s.userRepo.Create(ctx, domain.UserCreate{
		Email:        email,
		PasswordHash: hash,
	})
	if err != nil {
		s.logger.Error("failed to create user", "error", err)
		return AuthResult{}, err
	}

	// Create email verification token
	rawToken, err := s.tokenService.CreateToken(ctx, user.ID, domain.TokenTypeVerifyEmail)
	if err != nil {
		s.logger.Error("failed to create verification token", "error", err)
		// User was created, return success but log the token error
		return AuthResult{User: user}, nil
	}

	return AuthResult{
		User:  user,
		Token: rawToken,
	}, nil
}

// LoginUser authenticates a user with email and password.
func (s *AuthService) LoginUser(ctx context.Context, email, password string) (domain.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, autherr.ErrUserNotFound) {
			return domain.User{}, autherr.ErrInvalidCredentials
		}
		return domain.User{}, err
	}

	if err := s.hasher.Compare(user.PasswordHash, password); err != nil {
		return domain.User{}, autherr.ErrInvalidCredentials
	}

	return user, nil
}

// CreateEmailVerificationToken creates a new email verification token.
func (s *AuthService) CreateEmailVerificationToken(ctx context.Context, userID string) (string, error) {
	return s.tokenService.CreateToken(ctx, userID, domain.TokenTypeVerifyEmail)
}

// VerifyEmail verifies a user's email using the token.
func (s *AuthService) VerifyEmail(ctx context.Context, rawToken string) error {
	userID, err := s.tokenService.VerifyToken(ctx, rawToken, domain.TokenTypeVerifyEmail)
	if err != nil {
		return err
	}

	return s.userRepo.SetEmailVerified(ctx, userID)
}

// CreateResendEmailVerificationToken creates a new verification token and returns user email.
func (s *AuthService) CreateResendEmailVerificationToken(ctx context.Context, userID string) (token string, email string, err error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return "", "", err
	}

	token, err = s.tokenService.CreateToken(ctx, userID, domain.TokenTypeVerifyEmail)
	if err != nil {
		return "", "", err
	}

	return token, user.Email, nil
}

// CreatePasswordResetToken creates a password reset token for the email.
func (s *AuthService) CreatePasswordResetToken(ctx context.Context, email string) (string, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	return s.tokenService.CreateToken(ctx, user.ID, domain.TokenTypeForgetPassword)
}

// VerifyPasswordResetToken verifies a password reset token and returns user ID.
func (s *AuthService) VerifyPasswordResetToken(ctx context.Context, rawToken string) (string, error) {
	return s.tokenService.VerifyToken(ctx, rawToken, domain.TokenTypeForgetPassword)
}

// ChangePassword updates a user's password.
func (s *AuthService) ChangePassword(ctx context.Context, userID, newPassword string) error {
	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return autherr.ErrPasswordHash
	}

	return s.userRepo.UpdatePassword(ctx, userID, hash)
}

// GetUserByID retrieves a user by ID.
func (s *AuthService) GetUserByID(ctx context.Context, userID string) (domain.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

// PublicUser is a user representation safe for external use.
type PublicUser struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	IsVerified bool      `json:"is_verified"`
	CreatedAt  time.Time `json:"created_at"`
}

// ToPublic converts a domain user to a public representation.
func ToPublic(u domain.User) PublicUser {
	return PublicUser{
		ID:         u.ID,
		Email:      u.Email,
		IsVerified: u.IsVerified,
		CreatedAt:  u.CreatedAt,
	}
}
