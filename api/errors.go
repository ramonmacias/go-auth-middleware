package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

var (
	// UnauthorizedError used for all the Unauthorized requests (401)
	UnauthorizedError = Error{
		Type:       http.StatusText(http.StatusUnauthorized),
		Message:    "We can't authenticate you",
		StatusCode: http.StatusUnauthorized,
	}
	// RefreshTokenError used for the specific Unauthorized error related
	// with refresh token error
	RefreshTokenError = Error{
		Type:       "Refresh token",
		Message:    "Your token has expired",
		StatusCode: http.StatusUnauthorized,
	}
	// ForbiddenError used for all the Forbidden requests (403)
	ForbiddenError = Error{
		Type:       http.StatusText(http.StatusForbidden),
		Message:    "You don't have permission for this resource",
		StatusCode: http.StatusForbidden,
	}
	// TokenExpiredError used for the specific Unauthorized error related
	// with token expired error
	TokenExpiredError = Error{
		Type:       http.StatusText(http.StatusUnauthorized),
		Message:    "Your token has expired",
		StatusCode: http.StatusUnauthorized,
	}
)

// Error keep the structure for response with errors using json format
type Error struct {
	Type       string `json:"type,omitempty"`
	Message    string `json:"message,omitempty"`
	StatusCode int    `json:"-"`
}

// Error implements the error interface, so we can use this on calls inside other
// layers
func (e *Error) Error() string {
	return fmt.Sprintf("Error type: %s - message: %s", e.Type, e.Message)
}

// WriteResponse method will encode the Error e into a json payload
func (e Error) WriteResponse(wr http.ResponseWriter) {
	wr.Header().Set("Content-Type", "application/json")
	wr.WriteHeader(e.StatusCode)
	json.NewEncoder(wr).Encode(e)
}
