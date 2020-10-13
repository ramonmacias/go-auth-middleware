package middleware_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/ramonmacias/go-auth-middleware/auth"
	"github.com/ramonmacias/go-auth-middleware/middleware"
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
