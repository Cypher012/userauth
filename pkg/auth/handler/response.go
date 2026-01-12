package handler

import (
	"encoding/json"
	"net/http"
)

// AuthResponse is the response for successful authentication.
type AuthResponse struct {
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

// MessageResponse is a simple message response.
type MessageResponse struct {
	Message string `json:"message"`
}

// ErrorResponse is the response for errors.
type ErrorResponse struct {
	Error string `json:"error"`
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, ErrorResponse{Error: message})
}

// writeMessage writes a message response.
func writeMessage(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, MessageResponse{Message: message})
}

// decodeJSON decodes a JSON request body.
func decodeJSON[T any](w http.ResponseWriter, r *http.Request, dst *T) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}
