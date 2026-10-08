// Copyright (c) 2024 OData MCP Contributors
// SPDX-License-Identifier: MIT

package btp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

type userJWTKey struct{}

// WithUserJWT stores the caller's JWT in ctx. When present, the connectivity
// transport forwards it as SAP-Connectivity-Authentication so the Cloud
// Connector can perform principal propagation. Without it, the request runs
// as the technical user configured on the destination/basic auth.
func WithUserJWT(ctx context.Context, jwt string) context.Context {
	return context.WithValue(ctx, userJWTKey{}, jwt)
}

func userJWT(ctx context.Context) string {
	v, _ := ctx.Value(userJWTKey{}).(string)
	return v
}

// ConnectivityTransport routes plain-HTTP requests for virtual hosts through the
// BTP connectivity proxy to the Cloud Connector.
type ConnectivityTransport struct {
	base   *http.Transport
	tokens *TokenSource
}

// NewConnectivityTransport builds a transport from a connectivity-service binding.
func NewConnectivityTransport(c Credentials) (*ConnectivityTransport, error) {
	if c.ProxyHost == "" || c.ProxyPort.String() == "" {
		return nil, fmt.Errorf("connectivity binding has no on-premise proxy host/port")
	}
	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort(c.ProxyHost, c.ProxyPort.String())}
	return &ConnectivityTransport{
		base: &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			MaxIdleConns:          20,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
		tokens: NewTokenSource(c, nil),
	}, nil
}

// RoundTrip implements http.RoundTripper.
func (t *ConnectivityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.tokens.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("connectivity token: %w", err)
	}
	r := req.Clone(req.Context())
	r.Header.Set("Proxy-Authorization", "Bearer "+tok)
	// Never let a caller-supplied value impersonate a user to the Cloud Connector.
	r.Header.Del("SAP-Connectivity-Authentication")
	if jwt := userJWT(req.Context()); jwt != "" {
		r.Header.Set("SAP-Connectivity-Authentication", "Bearer "+jwt)
	}
	return t.base.RoundTrip(r)
}
