package auth_test

import (
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/ramonmacias/go-auth-middleware/auth"
	"github.com/robbert229/jwt"
	"github.com/stretchr/testify/assert"
)

func Test_basicCreationAndValidation(t *testing.T) {
	signingKey := "awesomeSigningKey"
	expiryTime := 2 * time.Hour
	s := auth.Session{
		Email:  "test@test.co",
		UserID: uuid.Must(uuid.NewV4()),
	}

	provider := auth.NewJWTProvider(signingKey, expiryTime)
	token, err := provider.Sign(s)
	assert.Nil(t, err)
	assert.NotEmpty(t, token)

	gotSession, err := provider.Validate(token)
	assert.Nil(t, err)
	assert.NotNil(t, gotSession)
	assert.Equal(t, s.Email, gotSession.Email)
	assert.Equal(t, s.UserID, gotSession.UserID)
}

func Test_expiredTokenValidation(t *testing.T) {
	expectedEmail := "test@test.co"
	expectedUserID := uuid.Must(uuid.NewV4())
	signingKey := "muzIsASecureSigningKey"
	algorithm := jwt.HmacSha512(signingKey)
	tokenExpirationTime := time.Minute * 5

	claims := jwt.NewClaim()
	claims.Set("Email", expectedEmail)
	claims.Set("UserID", expectedUserID)
	claims.SetTime("exp", time.Now().Add(-1))
	expiredToken, err := algorithm.Encode(claims)
	assert.Nil(t, err)

	provider := auth.NewJWTProvider(signingKey, tokenExpirationTime)
	_, err = provider.Validate(expiredToken)
	assert.Equal(t, auth.ErrTokenExpired, err)
}

func Test_refreshExpiredToken(t *testing.T) {
	expectedEmail := "test@test.co"
	expectedUserID := uuid.Must(uuid.NewV4())
	signingKey := "muzIsASecureSigningKey"
	algorithm := jwt.HmacSha512(signingKey)
	tokenExpirationTime := time.Minute * 5

	claims := jwt.NewClaim()
	claims.Set("Email", expectedEmail)
	claims.Set("UserID", expectedUserID)
	claims.SetTime("exp", time.Now().Add(-1))
	expiredToken, err := algorithm.Encode(claims)
	assert.Nil(t, err)

	provider := auth.NewJWTProvider(signingKey, tokenExpirationTime)
	_, err = provider.Validate(expiredToken)
	assert.Equal(t, auth.ErrTokenExpired, err)

	token, err := provider.Refresh(expiredToken)
	assert.Nil(t, err)
	assert.NotEmpty(t, token)

	session, err := provider.Validate(token)
	assert.Nil(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, expectedEmail, session.Email)
	assert.Equal(t, expectedUserID, session.UserID)
}
