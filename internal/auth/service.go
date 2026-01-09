package auth

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/Cypher012/userauth/internal/security"
	"github.com/Cypher012/userauth/internal/token"
)

var (
	ErrPasswordHash = errors.New("password hashing failed")
	ErrInvalidLogin = errors.New("invalid email or password")
)

type User struct {
	ID         string
	Email      string
	IsVerified bool
	IsActive   bool
	CreatedAt  time.Time
}

type AuthService struct {
	repo  *AuthRepository
	token *token.TokenService
}

func NewAuthService(repo *AuthRepository, token *token.TokenService) *AuthService {
	return &AuthService{
		repo:  repo,
		token: token,
	}
}

func (s *AuthService) RegisterUser(ctx context.Context, email, password string) (User, error) {
	_, err := s.repo.GetUserByEmail(ctx, email)
	switch {
	case err == nil:
		return User{}, ErrUserAlreadyExists
	case !errors.Is(err, ErrUserNotFound):
		log.Println(err.Error())
		return User{}, err
	}

	hashedPassword, err := security.GenerateHashPassword(password)
	if err != nil {
		return User{}, ErrPasswordHash
	}

	createUserRow, err := s.repo.CreateUser(ctx, email, hashedPassword)

	if err != nil {
		return User{}, err
	}

	return User{
		ID:         createUserRow.ID.String(),
		Email:      createUserRow.Email,
		IsVerified: createUserRow.IsVerified,
		IsActive:   createUserRow.IsActive,
		CreatedAt:  createUserRow.CreatedAt.Time,
	}, nil
}

func (s *AuthService) LoginUser(ctx context.Context, email, password string) (User, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return User{}, ErrInvalidLogin
	}

	if err := security.ComparePassword(user.PasswordHash, password); err != nil {
		return User{}, ErrInvalidLogin
	}

	return User{
		ID:         user.ID.String(),
		Email:      user.Email,
		IsVerified: user.IsVerified,
		IsActive:   user.IsActive,
		CreatedAt:  user.CreatedAt.Time,
	}, nil
}

func (s *AuthService) CreateVerificationToken(
	ctx context.Context,
	userID, email string,
) (string, error) {
	return s.token.CreateVerificationEmailToken(ctx, userID, email)
}
