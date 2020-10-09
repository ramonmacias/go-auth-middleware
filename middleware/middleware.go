package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/ramonmacias/go-auth-middleware/api"
	"github.com/ramonmacias/go-auth-middleware/auth"
)

// ValidForRefresh is a function that can be used for give an
// extra context on the middleware about is the business layer
// accept this user as a valid user
type ValidForRefresh func(userSession *auth.Session) error

// AuthAPI is the middleware that will check for the authorization header
// and apply all the validations needed to let the user let in or answer back
// with the correct Unauthorized errors
func AuthAPI(provider auth.Provider, fn ValidForRefresh) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			bearerToken := getBearerToken(req)
			if bearerToken == "" {
				api.UnauthorizedError.WriteResponse(w)
				return
			}
			session, err := provider.Validate(bearerToken)
			if err != nil {
				if errors.Is(err, auth.ErrTokenExpired) {
					if err := fn(session); err != nil {
						api.RefreshTokenError.WriteResponse(w)
						return
					}
				}
				api.ForbiddenError.WriteResponse(w)
				return
			}
			next.ServeHTTP(w, RequestWithSessionContext(req, session))
			return
		})
	}
}

// RequestWithSessionContext will create a new request and will attach the session
// in the context of the request
func RequestWithSessionContext(req *http.Request, userSession *auth.Session) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), struct{}{}, *userSession))
}

// GetSessionFromContext will take the authorized session shared on the
// http request
func GetSessionFromContext(req *http.Request) auth.Session {
	ctx := req.Context().Value(struct{}{})
	if session, ok := ctx.(auth.Session); ok {
		return session
	}
	return auth.Session{}
}

// getBearerToken function will get the token for the given
// request
func getBearerToken(req *http.Request) string {
	authHeader := req.Header.Get("Authorization")
	token := strings.Split(authHeader, " ")
	if len(token) != 2 && token[0] != "Bearer" {
		return ""
	}
	return token[1]
}
