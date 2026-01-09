package authhttp

import (
	"errors"
	"log"
	"net/http"

	"github.com/Cypher012/userauth/internal/auth"
	"github.com/Cypher012/userauth/internal/email"
	"github.com/Cypher012/userauth/internal/http/httputil"
)

type AuthHandler struct {
	service *auth.AuthService
	email   *email.EmailService
	jwt     *auth.JWTAuth
}

func NewAuthHandler(service *auth.AuthService, email *email.EmailService, jwt *auth.JWTAuth) *AuthHandler {
	return &AuthHandler{
		service: service,
		email:   email,
		jwt:     jwt,
	}
}

func (h *AuthHandler) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req UserAuthRequest

	if !httputil.DecodeJSONBody[UserAuthRequest](w, r, &req) {
		return
	}

	if req.Email == "" || req.Password == "" {
		httputil.ErrorResponse(w, http.StatusBadRequest, "email and password are required")
		return
	}

	user, err := h.service.RegisterUser(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUserAlreadyExists):
			httputil.ErrorResponse(w, http.StatusConflict, err.Error())
		default:
			httputil.ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	atkToken, rtkToken, err := h.jwt.GenerateToken(user.ID)
	if err != nil {
		httputil.ErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	rawToken, err := h.service.CreateVerificationToken(
		r.Context(),
		user.ID,
		user.Email,
	)
	if err != nil {
		httputil.ErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	go func(email, token string) {
		log.Printf("sending verify email to %s...", email)
		if err := h.email.SendVerifyEmail(email, token); err != nil {
			log.Printf("verify email failed: %v", err)
		} else {
			log.Printf("verify email sent successfully to %s", email)
		}
	}(user.Email, rawToken)

	payload := UserResponse{
		Message: "User sign up succesful",
		Auth: Auth{
			Atk: atkToken,
			Rtk: rtkToken,
		},
	}

	httputil.JSONReponse(w, http.StatusCreated, payload)
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req UserAuthRequest

	if !httputil.DecodeJSONBody[UserAuthRequest](w, r, &req) {
		return
	}

	if req.Email == "" || req.Password == "" {
		httputil.ErrorResponse(w, http.StatusBadRequest, "email and password are required")
		return
	}

	user, err := h.service.LoginUser(r.Context(), req.Email, req.Password)

	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidLogin):
			httputil.ErrorResponse(w, http.StatusUnauthorized, err.Error())
		default:
			httputil.ErrorResponse(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	atkToken, rtkToken, err := h.jwt.GenerateToken(user.ID)
	if err != nil {
		httputil.ErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	payload := UserResponse{
		Message: "User sign in successful",
		Auth: Auth{
			Atk: atkToken,
			Rtk: rtkToken,
		},
	}

	httputil.JSONReponse(w, http.StatusOK, payload)
}

func (h *AuthHandler) VerifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
}

func (h *AuthHandler) ResendVerifyHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
}

func (h *AuthHandler) ForgetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
}

func (h *AuthHandler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
}

func (h *AuthHandler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
}
