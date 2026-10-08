// Copyright (c) 2024 OData MCP Contributors
// SPDX-License-Identifier: MIT

package btp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenSource fetches and caches client-credentials tokens for a service binding.
// These are technical tokens (e.g. for the connectivity proxy), never user tokens.
type TokenSource struct {
	creds  Credentials
	client *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewTokenSource creates a TokenSource; a nil client uses a default with timeout.
func NewTokenSource(c Credentials, client *http.Client) *TokenSource {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &TokenSource{creds: c, client: client}
}

// Token returns a valid access token, refreshing it shortly before expiry.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().Before(s.expires) {
		return s.token, nil
	}

	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(s.creds.URL, "/")+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(s.creds.ClientID, s.creds.ClientSecret)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned an unusable response")
	}
	s.token = out.AccessToken
	// Refresh a minute early, but never hold a token longer than it is valid.
	ttl := time.Duration(out.ExpiresIn)*time.Second - time.Minute
	if ttl < 0 {
		ttl = 0
	}
	s.expires = time.Now().Add(ttl)
	return s.token, nil
}
