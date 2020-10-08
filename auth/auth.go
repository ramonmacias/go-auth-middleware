package auth

import (
	"errors"

	"github.com/gofrs/uuid"
)

var (
	// ErrMandatorySessionFields is a specific error used for we don't have all the
	// mandatory fields on the token claims
	ErrMandatorySessionFields = errors.New("Email and UserID are mandatory fields")
	// ErrTokenExpired is a specific error used for determine when a given token
	// is no longer valid due a time constraints
	ErrTokenExpired = errors.New("Token expired")
)

// Session type encapsulates the basic information
// for identifier a user
type Session struct {
	Email  string
	UserID uuid.UUID
}

// Provider interface defines which method should be
// implemented in order to becom an auth.Provider
type Provider interface {
	Sign(s Session) (string, error)
	Refresh(token string) (string, error)
	Validate(token string) (*Session, error)
}
