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
// with the correct Unauthorized errors, the ValidForRefresh function is mandatory
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
					if err := fn(session); err == nil {
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

// CookieAPI is the middleware that will check for the validness of the given token
// on the given cookie, this middleware will answer back with a valid refreshed token,
// expiring the token if needed or with the same cookie in the valid case.
func CookieAPI(provider auth.Provider, fn ValidForRefresh, cookieService auth.CookieService) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			cookie, err := req.Cookie("bearer-token")
			if err != nil {
				api.ForbiddenError.WriteResponse(w)
				return
			}
			session, err := provider.Validate(cookie.Value)
			if err != nil {
				if errors.Is(err, auth.ErrTokenExpired) {
					if err := fn(session); err == nil {
						token, err := provider.Refresh(cookie.Value)
						if err != nil {
							cookieService.Set(w, auth.ExpiredCookie())
							return
						}
						cookieService.Set(w, auth.Cookie(token))
						return
					}
				}
				cookieService.Set(w, auth.ExpiredCookie())
				return
			}
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
