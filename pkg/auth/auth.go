package auth

import (
	"net/http"

	"github.com/Cypher012/userauth/pkg/auth/handler"
	"github.com/Cypher012/userauth/pkg/auth/ports"
	"github.com/Cypher012/userauth/pkg/auth/service"
	"github.com/go-chi/chi/v5"
)

// Module is the main entry point for the auth package.
// It contains all the wired-up components and provides route registration.
type Module struct {
	config        Config
	authService   *service.AuthService
	tokenService  *service.TokenService
	handler       *handler.Handler
	jwtProvider   ports.JWTProvider
	cookieManager ports.CookieManager
}

// Dependencies contains all external dependencies for the auth module.
type Dependencies struct {
	// Required
	UserRepository       ports.UserRepository
	EmailTokenRepository ports.EmailTokenRepository
	PasswordHasher       ports.PasswordHasher
	TokenGenerator       ports.TokenGenerator
	JWTProvider          ports.JWTProvider
	CookieManager        ports.CookieManager

	// Optional
	EmailSender ports.EmailSender // If nil, emails won't be sent
	Logger      ports.Logger      // If nil, uses no-op logger
}

// New creates a new auth Module with the given configuration and dependencies.
func New(cfg Config, deps Dependencies) (*Module, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Set defaults
	if deps.Logger == nil {
		deps.Logger = ports.DefaultLogger{}
	}

	// Create token service
	tokenService := service.NewTokenService(
		deps.EmailTokenRepository,
		deps.TokenGenerator,
		cfg.EmailTokenTTL,
	)

	// Create auth service
	authService := service.NewAuthService(
		deps.UserRepository,
		tokenService,
		deps.PasswordHasher,
		deps.Logger,
	)

	// Create handler
	h := handler.New(handler.Config{
		AuthService:   authService,
		JWTProvider:   deps.JWTProvider,
		CookieManager: deps.CookieManager,
		EmailSender:   deps.EmailSender,
		Logger:        deps.Logger,
		BaseURL:       cfg.BaseURL + cfg.RoutePrefix,
	})

	return &Module{
		config:        cfg,
		authService:   authService,
		tokenService:  tokenService,
		handler:       h,
		jwtProvider:   deps.JWTProvider,
		cookieManager: deps.CookieManager,
	}, nil
}

// RegisterRoutes mounts auth routes on the given router.
// Routes are mounted relative to the router's current path.
//
// Registered routes:
//   - POST /signup           - User registration
//   - POST /login            - User login
//   - POST /logout           - User logout
//   - GET  /verify-email/{token}  - Email verification
//   - POST /verify-email/resend   - Resend verification email (requires auth)
//   - POST /forgot-password       - Initiate password reset
//   - POST /reset-password/{token} - Complete password reset
//   - POST /refresh               - Refresh access token (requires refresh token)
func (m *Module) RegisterRoutes(r chi.Router) {
	r.Post("/signup", m.handler.SignUp)
	r.Post("/login", m.handler.Login)
	r.Post("/logout", m.handler.Logout)
	r.Get("/verify-email/{token}", m.handler.VerifyEmail)
	r.Post("/forgot-password", m.handler.ForgotPassword)
	r.Post("/reset-password/{token}", m.handler.ResetPassword)

	// Protected routes
	r.With(m.jwtProvider.AccessMiddleware).
		Post("/verify-email/resend", m.handler.ResendVerificationEmail)

	r.With(m.jwtProvider.RefreshMiddleware).
		Post("/refresh", m.handler.RefreshToken)
}

// Router returns a new chi.Router with auth routes already registered.
// Useful when you want to mount the entire auth module at a specific path.
func (m *Module) Router() chi.Router {
	r := chi.NewRouter()
	m.RegisterRoutes(r)
	return r
}

// AuthService returns the underlying auth service for advanced use cases.
func (m *Module) AuthService() *service.AuthService {
	return m.authService
}

// JWTProvider returns the JWT provider for use in other parts of the app.
func (m *Module) JWTProvider() ports.JWTProvider {
	return m.jwtProvider
}

// AccessMiddleware returns middleware for protecting routes with access tokens.
func (m *Module) AccessMiddleware() func(http.Handler) http.Handler {
	return m.jwtProvider.AccessMiddleware
}

// RefreshMiddleware returns middleware for routes requiring refresh tokens.
func (m *Module) RefreshMiddleware() func(http.Handler) http.Handler {
	return m.jwtProvider.RefreshMiddleware
}
