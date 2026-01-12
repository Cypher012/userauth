package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Cypher012/userauth/pkg/auth/autherr"
	"github.com/Cypher012/userauth/pkg/auth/ports"
	"github.com/Cypher012/userauth/pkg/auth/service"
	"github.com/go-chi/chi/v5"
)

// Handler handles HTTP requests for authentication.
type Handler struct {
	authService   *service.AuthService
	jwtProvider   ports.JWTProvider
	cookieManager ports.CookieManager
	emailSender   ports.EmailSender
	logger        ports.Logger
	baseURL       string

	// Callbacks for customization
	onVerifySuccess http.HandlerFunc
	onVerifyError   http.HandlerFunc
}

// Config holds handler configuration.
type Config struct {
	AuthService   *service.AuthService
	JWTProvider   ports.JWTProvider
	CookieManager ports.CookieManager
	EmailSender   ports.EmailSender
	Logger        ports.Logger
	BaseURL       string

	// Optional: custom handlers for verification result pages
	OnVerifySuccess http.HandlerFunc
	OnVerifyError   http.HandlerFunc
}

// New creates a new Handler.
func New(cfg Config) *Handler {
	if cfg.Logger == nil {
		cfg.Logger = ports.DefaultLogger{}
	}

	h := &Handler{
		authService:   cfg.AuthService,
		jwtProvider:   cfg.JWTProvider,
		cookieManager: cfg.CookieManager,
		emailSender:   cfg.EmailSender,
		logger:        cfg.Logger,
		baseURL:       cfg.BaseURL,
	}

	// Set default verification handlers
	if cfg.OnVerifySuccess != nil {
		h.onVerifySuccess = cfg.OnVerifySuccess
	} else {
		h.onVerifySuccess = h.defaultVerifySuccess
	}

	if cfg.OnVerifyError != nil {
		h.onVerifyError = cfg.OnVerifyError
	} else {
		h.onVerifyError = h.defaultVerifyError
	}

	return h
}

// SignUp handles user registration.
func (h *Handler) SignUp(w http.ResponseWriter, r *http.Request) {
	var req SignUpRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	result, err := h.authService.RegisterUser(r.Context(), req.Email, req.Password)
	if err != nil {
		h.handleError(w, err)
		return
	}

	// Generate JWT tokens
	accessToken, refreshToken, err := h.jwtProvider.GenerateTokenPair(result.User.ID)
	if err != nil {
		h.logger.Error("failed to generate tokens", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	// Set refresh token cookie
	h.cookieManager.SetRefreshToken(w, refreshToken)

	// Send verification email asynchronously
	if result.Token != "" && h.emailSender != nil {
		go func(email, token string) {
			verifyURL := fmt.Sprintf("%s/verify-email/%s", h.baseURL, token)
			if err := h.emailSender.SendVerificationEmail(email, verifyURL); err != nil {
				h.logger.Error("failed to send verification email", "email", email, "error", err)
			}
		}(result.User.Email, result.Token)
	}

	writeJSON(w, http.StatusCreated, AuthResponse{
		Message: "User registered successfully. Please check your email to verify your account.",
		Token:   accessToken,
	})
}

// Login handles user authentication.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	user, err := h.authService.LoginUser(r.Context(), req.Email, req.Password)
	if err != nil {
		h.handleError(w, err)
		return
	}

	accessToken, refreshToken, err := h.jwtProvider.GenerateTokenPair(user.ID)
	if err != nil {
		h.logger.Error("failed to generate tokens", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	h.cookieManager.SetRefreshToken(w, refreshToken)

	writeJSON(w, http.StatusOK, AuthResponse{
		Message: "Login successful",
		Token:   accessToken,
	})
}

// VerifyEmail handles email verification via token in URL.
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		h.onVerifyError(w, r)
		return
	}

	if err := h.authService.VerifyEmail(r.Context(), token); err != nil {
		h.logger.Error("email verification failed", "error", err)
		h.onVerifyError(w, r)
		return
	}

	h.onVerifySuccess(w, r)
}

// ResendVerificationEmail resends the verification email.
func (h *Handler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	claims, err := h.jwtProvider.ExtractClaimsFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	token, email, err := h.authService.CreateResendEmailVerificationToken(r.Context(), claims.UserID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	if h.emailSender != nil {
		go func(email, token string) {
			verifyURL := fmt.Sprintf("%s/verify-email/%s", h.baseURL, token)
			if err := h.emailSender.SendVerificationEmail(email, verifyURL); err != nil {
				h.logger.Error("failed to send verification email", "email", email, "error", err)
			}
		}(email, token)
	}

	writeMessage(w, http.StatusOK, "Verification email sent")
}

// ForgotPassword initiates password reset.
func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}

	token, err := h.authService.CreatePasswordResetToken(r.Context(), req.Email)
	if err != nil {
		// Don't reveal if email exists
		if errors.Is(err, autherr.ErrUserNotFound) {
			writeMessage(w, http.StatusOK, "If the email exists, a password reset link will be sent")
			return
		}
		h.handleError(w, err)
		return
	}

	if h.emailSender != nil {
		go func(email, token string) {
			resetURL := fmt.Sprintf("%s/reset-password/%s", h.baseURL, token)
			if err := h.emailSender.SendPasswordResetEmail(email, resetURL); err != nil {
				h.logger.Error("failed to send password reset email", "email", email, "error", err)
			}
		}(req.Email, token)
	}

	writeMessage(w, http.StatusOK, "If the email exists, a password reset link will be sent")
}

// ResetPassword completes password reset.
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	var req ResetPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	userID, err := h.authService.VerifyPasswordResetToken(r.Context(), token)
	if err != nil {
		h.handleError(w, err)
		return
	}

	if err := h.authService.ChangePassword(r.Context(), userID, req.Password); err != nil {
		h.handleError(w, err)
		return
	}

	writeMessage(w, http.StatusOK, "Password has been reset successfully")
}

// RefreshToken handles token refresh.
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	claims, err := h.jwtProvider.ExtractClaimsFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	accessToken, refreshToken, err := h.jwtProvider.GenerateTokenPair(claims.UserID)
	if err != nil {
		h.logger.Error("failed to generate tokens", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	h.cookieManager.SetRefreshToken(w, refreshToken)

	writeJSON(w, http.StatusOK, AuthResponse{
		Message: "Token refreshed",
		Token:   accessToken,
	})
}

// Logout clears the refresh token cookie.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	h.cookieManager.ClearRefreshToken(w)
	writeMessage(w, http.StatusOK, "Logged out successfully")
}

// handleError maps domain errors to HTTP responses.
func (h *Handler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, autherr.ErrUserAlreadyExists):
		writeError(w, http.StatusConflict, "user already exists")
	case errors.Is(err, autherr.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid email or password")
	case errors.Is(err, autherr.ErrUserNotFound):
		writeError(w, http.StatusNotFound, "user not found")
	case errors.Is(err, autherr.ErrTokenInvalid), errors.Is(err, autherr.ErrTokenExpired), errors.Is(err, autherr.ErrTokenUsed):
		writeError(w, http.StatusBadRequest, "invalid or expired token")
	case errors.Is(err, autherr.ErrPasswordHash):
		writeError(w, http.StatusInternalServerError, "failed to process password")
	default:
		h.logger.Error("unhandled error", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}

// Default verification handlers
func (h *Handler) defaultVerifySuccess(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Email Verified</title></head>
<body>
<h1>Email Verified Successfully!</h1>
<p>You can now close this page and log in to your account.</p>
</body>
</html>`))
}

func (h *Handler) defaultVerifyError(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Verification Failed</title></head>
<body>
<h1>Email Verification Failed</h1>
<p>The verification link is invalid or has expired.</p>
</body>
</html>`))
}
