package handler

// SignUpRequest is the request body for user registration.
type SignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest is the request body for user login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ForgotPasswordRequest is the request body for password reset initiation.
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// ResetPasswordRequest is the request body for password reset completion.
type ResetPasswordRequest struct {
	Password string `json:"password"`
}
