// Copyright (c) 2024 OData MCP Contributors
// SPDX-License-Identifier: MIT

// Package btp holds SAP BTP (Cloud Foundry) integration: service bindings,
// service tokens and the connectivity proxy used to reach on-premise systems
// through the Cloud Connector.
package btp

import (
	"encoding/json"
	"fmt"
	"os"
)

// Credentials is the subset of service-binding credentials this package uses.
// Port numbers arrive as JSON strings or numbers depending on the service.
type Credentials struct {
	ClientID     string      `json:"clientid"`
	ClientSecret string      `json:"clientsecret"`
	URL          string      `json:"url"` // UAA base URL (token endpoint is URL + /oauth/token)
	URI          string      `json:"uri"` // Destination service base URI
	ProxyHost    string      `json:"onpremise_proxy_host"`
	ProxyPort    json.Number `json:"onpremise_proxy_http_port"`
}

type binding struct {
	Name        string      `json:"name"`
	Credentials Credentials `json:"credentials"`
}

// Bindings are the parsed VCAP_SERVICES entries keyed by service label.
type Bindings map[string][]binding

// ParseVCAP parses a VCAP_SERVICES document.
func ParseVCAP(raw string) (Bindings, error) {
	var b Bindings
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, fmt.Errorf("invalid VCAP_SERVICES: %w", err)
	}
	return b, nil
}

// FromEnv parses VCAP_SERVICES from the environment; it returns nil (no error)
// when the variable is unset, i.e. when not running on Cloud Foundry.
func FromEnv() (Bindings, error) {
	raw := os.Getenv("VCAP_SERVICES")
	if raw == "" {
		return nil, nil
	}
	return ParseVCAP(raw)
}

// First returns the credentials of the first binding with the given service label
// ("connectivity", "destination", "xsuaa", ...).
func (b Bindings) First(label string) (Credentials, bool) {
	if list := b[label]; len(list) > 0 {
		return list[0].Credentials, true
	}
	return Credentials{}, false
}
