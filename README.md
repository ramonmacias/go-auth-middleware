# Auth Middleware in Go
[![Go Report Card](https://goreportcard.com/badge/github.com/ramonmacias/go-auth-middleware)](https://goreportcard.com/report/github.com/ramonmacias/go-auth-middleware) [![GoDoc](https://godoc.org/github.com/ramonmacias/go-auth-middleware?status.svg)](https://godoc.org/github.com/ramonmacias/go-auth-middleware)


The aim of this project is to provide a way of implement an http middleware for authenticate http requests, using the Bearer token as a source of truth.

## Packages

This project has three different packages:

* api: this package provides an implementation of error interface for the api layer.
* auth: this package provides an auth.Provider interface, a JWT implementation of that interface and a cookies service.
* middleware: this package provides a two different approaches of how to implement the auth with a bearer token, one based on Authorization header and the other one based on cookies.

## Test

```
go test ./...
```

## How to use

On this project you will find two different approaches of how I managed the authentication request process, the first one is using the Authorization header and the second one is based on Cookies, both have advantatges and disadvantatges, so you can choose whatever suits better on your project. Both services are using https://github.com/gorilla/mux as a base for setup the server and his routes.

### Authorization header based

The authorization header approach will take the bearer token from the Authorization http header, using the value on this way **Bearer $TOKEN**, once it receives this token, the middleware will check if the token is valid or not, if is not valid, it could be because is expired, so we will check if we are allowed to refresh the token and answer back with a specific refresh token error message, this kind of error should we used from the client in order to ask for a new refreshed token. If the token is invalid or mallformed, the middleware will answer back with a forbidden or unathorized errors. If the token is valid, then the request will reach the final handler, adding on the context request the given session.


In order to add this middleware on your routing:

```
router := mux.NewRouter()
router.HandleFunc("/", sampleHandler)
router.Use(middleware.AuthAPI(authProvider, middleware.ValidForRefresh()))
```

Then your sampleHandler should be something like this:

```
func sampleHandler(wr http.ResponseWriter, r *http.Request) {
  session := middleware.GetSessionFromContext(r)
  // Add here the rest of the handler logic
}
```

### Cookie based

The Cookie based approach is working similar to the Authorization header, but the main difference is that we use a cookie for transport the token between the client and the server. On this case we need use a cookie named **bearer-token** and inside the cookie value we should have our token. Once the request reach our middleware we will validate the token inside the cookie, in case the token is expired and we are able to refresh it, we will do it and we are going to update the token in the cookie so we can keep the session alive, in case the token is not valid we will expire the cookie, so the client need to ask for a new cookie (login). If the token is valid then the request will reach the final hanlder keeping the session on the request context.

In order to add this middleware on your routing:

```
router := mux.NewRouter()
router.HandleFunc("/", sampleHandler)
router.Use(middleware.AuthCookieAPI(authProvider, middleware.ValidForRefresh()))
```

Then your sampleHandler should be something like this:

```
func sampleHandler(wr http.ResponseWriter, r *http.Request) {
  session := middleware.GetSessionFromContext(r)
  // Add here the rest of the handler logic
}
```
