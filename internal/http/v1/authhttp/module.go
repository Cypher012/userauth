package authhttp

import (
	"github.com/Cypher012/userauth/internal/auth"
	"github.com/Cypher012/userauth/internal/email"
	"github.com/Cypher012/userauth/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Module struct {
	Router chi.Router
}

func NewModule(
	pool *pgxpool.Pool,
	tokenSvc *token.TokenService,
	emailSvc *email.EmailService,
	jwt *auth.JWTAuth,
) *Module {

	repo := auth.NewAuthRepository(pool)
	service := auth.NewAuthService(repo, tokenSvc)
	handler := NewAuthHandler(service, emailSvc, jwt)

	r := chi.NewRouter()

	r.Post("/signup", handler.SignUpHandler)
	r.Post("/login", handler.LoginHandler)
	r.Post("/verify-email/{token}", handler.VerifyEmailHandler)
	r.Post("/verify-email/resend", handler.ResendVerifyHandler)
	r.Post("/forget-password", handler.ForgetPasswordHandler)
	r.Post("/reset-password", handler.ResetPasswordHandler)

	r.With(jwt.RefreshMiddleware).
		Post("/refresh", handler.RefreshTokenHandler)

	return &Module{
		Router: r,
	}
}
