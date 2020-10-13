package auth

import (
	"net/http"
	"time"
)

// CookieService will keep the basics for manage all the quicka cookies
type CookieService struct {
	host string
}

// NewCookieService will build a new service with the given host
func NewCookieService(host string) CookieService {
	return CookieService{
		host: host,
	}
}

// Set sets a cookie for Quicka
func (c CookieService) Set(wr http.ResponseWriter, fn func() *http.Cookie) {
	cookie := fn()
	cookie.Domain = c.host
	http.SetCookie(wr, cookie)
}

// Cookie will setup a new http.Cookie with the given
// token as a cookie value
func Cookie(token string) func() *http.Cookie {
	return func() *http.Cookie {
		return &http.Cookie{
			Name:    "bearer-token",
			Value:   token,
			Path:    "/",
			Expires: time.Now().UTC().Add(time.Hour * 24 * 30),
		}
	}
}

// ExpiredCookie will setup the auth cookie as
// expired
func ExpiredCookie() func() *http.Cookie {
	return func() *http.Cookie {
		return &http.Cookie{
			Name:   "bearer-token",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
			Expires: time.Date(
				1983, 7, 26, 20, 34, 58, 651387237, time.UTC),
		}
	}
}
