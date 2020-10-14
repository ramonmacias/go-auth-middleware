package middleware_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"github.com/ramonmacias/go-auth-middleware/api"
	"github.com/ramonmacias/go-auth-middleware/auth"
	"github.com/ramonmacias/go-auth-middleware/middleware"
	"github.com/robbert229/jwt"
	"github.com/stretchr/testify/assert"
)

func mockAlwaysValidRefresher() middleware.ValidForRefresh {
	return func(userSession *auth.Session) error {
		return nil
	}
}

func mockAlwaysInvalidRefresher() middleware.ValidForRefresh {
	return func(userSession *auth.Session) error {
		return errors.New("Can not refresh the session")
	}
}

func Test_noAuthHeader(t *testing.T) {
	signingKey := "hardSigningKey"
	expiryTime := 2 * time.Hour
	authProvider := auth.NewJWTProvider(signingKey, expiryTime)

	router := mux.NewRouter()
	router.HandleFunc("/", func(wr http.ResponseWriter, req *http.Request) {})
	router.Use(middleware.AuthAPI(authProvider, mockAlwaysValidRefresher()))

	wr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.Nil(t, err)

	router.ServeHTTP(wr, req)
	assert.Equal(t, http.StatusUnauthorized, wr.Code)
}

func Test_mallformedToken(t *testing.T) {
	signingKey := "hardSigningKey"
	expiryTime := 2 * time.Hour
	authProvider := auth.NewJWTProvider(signingKey, expiryTime)

	router := mux.NewRouter()
	router.HandleFunc("/", func(wr http.ResponseWriter, r *http.Request) {})
	router.Use(middleware.AuthAPI(authProvider, mockAlwaysValidRefresher()))

	wr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.Nil(t, err)
	req.Header.Set("Authorization", "Bearer invalidTestToken")

	router.ServeHTTP(wr, req)
	assert.Equal(t, http.StatusForbidden, wr.Code)
}

func Test_tokenExpired(t *testing.T) {
	expectedEmail := "test@test.co"
	signingKey := "hardSigningKey"
	algorithm := jwt.HmacSha512(signingKey)
	expiryTime := 2 * time.Hour
	expectedUserID := uuid.Must(uuid.NewV4())
	authProvider := auth.NewJWTProvider(signingKey, expiryTime)

	claims := jwt.NewClaim()
	claims.Set("Email", expectedEmail)
	claims.Set("UserID", expectedUserID)
	claims.SetTime("exp", time.Now().Add(-1))
	expiredToken, err := algorithm.Encode(claims)
	assert.Nil(t, err)

	router := mux.NewRouter()
	router.HandleFunc("/", func(wr http.ResponseWriter, r *http.Request) {})
	router.Use(middleware.AuthAPI(authProvider, mockAlwaysValidRefresher()))

	wr := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.Nil(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", expiredToken))

	router.ServeHTTP(wr, req)
	assert.Equal(t, http.StatusUnauthorized, wr.Code)
	apiErr := api.Error{}
	err = json.NewDecoder(wr.Body).Decode(&apiErr)
	assert.Nil(t, err)
	assert.Equal(t, api.RefreshTokenError.Message, apiErr.Message)
}
