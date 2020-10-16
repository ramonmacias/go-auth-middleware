# Auth Middleware in Go
[![Go Report Card](https://goreportcard.com/badge/github.com/ramonmacias/go-auth-middleware)](https://goreportcard.com/report/github.com/ramonmacias/go-auth-middleware) [![GoDoc]

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

