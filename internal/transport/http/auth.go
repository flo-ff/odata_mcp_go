// Copyright (c) 2024 OData MCP Contributors
// SPDX-License-Identifier: MIT

package http

import (
	"context"
	"errors"
	"net/http"
)

// Authenticator validates an incoming MCP HTTP request. On success it returns
// a context derived from the request context (e.g. carrying the caller's
// identity); on failure it returns an error and the request is rejected with 401.
type Authenticator interface {
	Authenticate(r *http.Request) (context.Context, error)
}

// AuthenticatorFunc adapts a function to the Authenticator interface.
type AuthenticatorFunc func(r *http.Request) (context.Context, error)

// Authenticate implements Authenticator.
func (f AuthenticatorFunc) Authenticate(r *http.Request) (context.Context, error) { return f(r) }

// StaticTokenAuthenticator accepts requests carrying "Authorization: Bearer <token>"
// that matches a single shared secret.
type StaticTokenAuthenticator struct {
	Token string
}

// Authenticate implements Authenticator.
func (a StaticTokenAuthenticator) Authenticate(r *http.Request) (context.Context, error) {
	provided := BearerToken(r.Header.Get("Authorization"))
	if a.Token == "" || provided == "" || !ValidateToken(provided, a.Token) {
		return nil, errors.New("invalid or missing bearer token")
	}
	return r.Context(), nil
}

// RequireAuth wraps next so that every request except the exempt paths must
// pass the authenticator. CORS preflight (OPTIONS) is passed through untouched.
// A nil authenticator disables the check.
func RequireAuth(next http.Handler, auth Authenticator, exemptPaths ...string) http.Handler {
	if auth == nil {
		return next
	}
	exempt := make(map[string]bool, len(exemptPaths))
	for _, p := range exemptPaths {
		exempt[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || exempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		ctx, err := auth.Authenticate(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="odata-mcp"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
