// Copyright (c) 2024 OData MCP Contributors
// SPDX-License-Identifier: MIT

package btp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseVCAP(t *testing.T) {
	b, err := ParseVCAP(`{"connectivity":[{"name":"c","credentials":{"clientid":"id","clientsecret":"s","url":"https://uaa","onpremise_proxy_host":"10.0.0.1","onpremise_proxy_http_port":"20003"}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := b.First("connectivity")
	if !ok || c.ProxyHost != "10.0.0.1" || c.ProxyPort.String() != "20003" {
		t.Fatalf("unexpected credentials: %+v", c)
	}
	if _, ok := b.First("destination"); ok {
		t.Fatal("unexpected destination binding")
	}
	// numeric port variant
	b, err = ParseVCAP(`{"connectivity":[{"credentials":{"onpremise_proxy_http_port":20003}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := b.First("connectivity"); c.ProxyPort.String() != "20003" {
		t.Fatal("numeric port not parsed")
	}
}

func TestTokenSourceCaches(t *testing.T) {
	calls := 0
	uaa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if u, p, _ := r.BasicAuth(); u != "id" || p != "s" || r.URL.Path != "/oauth/token" {
			t.Errorf("bad token request: %s %v", r.URL.Path, u)
		}
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
	defer uaa.Close()
	ts := NewTokenSource(Credentials{ClientID: "id", ClientSecret: "s", URL: uaa.URL}, nil)
	for i := 0; i < 3; i++ {
		if tok, err := ts.Token(context.Background()); err != nil || tok != "tok" {
			t.Fatalf("token: %q %v", tok, err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected 1 token call, got %d", calls)
	}
}

func TestConnectivityTransportHeaders(t *testing.T) {
	uaa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"conn-tok","expires_in":3600}`))
	}))
	defer uaa.Close()

	var got http.Header
	var gotURL string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, gotURL = r.Header.Clone(), r.URL.String()
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)

	tr, err := NewConnectivityTransport(Credentials{ClientID: "id", ClientSecret: "s", URL: uaa.URL,
		ProxyHost: pu.Hostname(), ProxyPort: "0"})
	if err != nil {
		t.Fatal(err)
	}
	tr.base.Proxy = http.ProxyURL(pu)

	do := func(ctx context.Context, spoof string) {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://s4.virtual:8000/sap/opu/odata/x/", nil)
		if spoof != "" {
			req.Header.Set("SAP-Connectivity-Authentication", spoof)
		}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	do(context.Background(), "Bearer spoofed")
	if got.Get("Proxy-Authorization") != "Bearer conn-tok" {
		t.Fatalf("proxy auth: %q", got.Get("Proxy-Authorization"))
	}
	if got.Get("SAP-Connectivity-Authentication") != "" {
		t.Fatal("spoofed user header must be stripped")
	}
	if !strings.HasPrefix(gotURL, "http://s4.virtual:8000/") {
		t.Fatalf("not proxied with absolute URL: %s", gotURL)
	}

	do(WithUserJWT(context.Background(), "user-jwt"), "")
	if got.Get("SAP-Connectivity-Authentication") != "Bearer user-jwt" {
		t.Fatalf("user jwt not propagated: %q", got.Get("SAP-Connectivity-Authentication"))
	}
}
