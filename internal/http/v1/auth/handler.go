package auth

import (
	"net/http"

	"github.com/Cypher012/userauth/internal/auth"
)

type AuthHandler struct {
	service *auth.AuthService
}

func NewAuthHandler(service *auth.AuthService) *AuthHandler {
	return &AuthHandler{
		service: service,
	}
}

func (h *AuthHandler) SignUpUserHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

}
