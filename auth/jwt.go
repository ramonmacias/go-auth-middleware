package auth

import (
	"errors"
	"time"

	"github.com/gofrs/uuid"
	"github.com/robbert229/jwt"
)

// This is a sample of how can be implemented
// the auth.Provider using JWT, this file in a real
// arch maybe shouldn't be here on the same package
// I put it here just for simplify the show case

// jwtProvider type keep the information needed for implement an auth provider
// based on jwt
type jwtProvider struct {
	signingKey     string
	expirationTime time.Duration
	algorithm      jwt.Algorithm
}

// NewJWTProvider will build a new auth.Provider based on a jwt implementation
func NewJWTProvider(signingKey string, tokenExpiryTime time.Duration) Provider {
	return &jwtProvider{
		signingKey:     signingKey,
		expirationTime: tokenExpiryTime,
		algorithm:      jwt.HmacSha512(signingKey),
	}
}

// Sign will generate a new signed JWT using the given Session
func (j *jwtProvider) Sign(s Session) (string, error) {
	return j.signClaims(map[string]interface{}{
		"Email":  s.Email,
		"UserID": s.UserID,
	})
}

// Refresh method will validate the given token and answer
// back with a new refreshed token
func (j *jwtProvider) Refresh(token string) (string, error) {
	claims, err := j.decodeAndValidateClaims(token)
	if err == nil || errors.Is(err, ErrTokenExpired) {
		claims.SetTime("exp", time.Now().Add(j.expirationTime))
		claims.SetTime("iat", time.Now())
		return j.algorithm.Encode(claims)
	}
	return "", err
}

func (j *jwtProvider) Validate(token string) (*Session, error) {
	claims, err := j.decodeAndValidateClaims(token)
	if err != nil {
		return nil, err
	}
	email, err := claims.Get("Email")
	if err != nil {
		return nil, err
	}
	userID, err := claims.Get("UserID")
	if err != nil {
		return nil, err
	}
	emailString, ok := email.(string)
	if !ok {
		return nil, ErrMandatorySessionFields
	}
	userIDString, ok := userID.(string)
	if !ok {
		return nil, ErrMandatorySessionFields
	}
	return &Session{
		Email:  emailString,
		UserID: uuid.FromStringOrNil(userIDString),
	}, err
}

// signedClaims method will receive a claimsValue that we will use to create a new
// signed token with the claims provided
func (j *jwtProvider) signClaims(claimsValue map[string]interface{}) (string, error) {
	claims := jwt.NewClaim()
	for key, val := range claimsValue {
		claims.Set(key, val)
	}
	claims.SetTime("exp", time.Now().Add(j.expirationTime))
	return j.algorithm.Encode(claims)
}

// decodeClaims method will receive the signed claims and the keys on the claims
// map, and will fill with the correct value, otherwise will return an error if
// some of the claims are missing
func (j *jwtProvider) decodeAndValidateClaims(signedClaims string) (*jwt.Claims, error) {
	claims, err := j.algorithm.DecodeAndValidate(signedClaims)
	if err != nil {
		// Check if is an expired error
		if err.Error() == "failed to validate exp: token has expired" {
			return nil, ErrTokenExpired
		}
		return nil, err
	}
	return claims, nil
}
