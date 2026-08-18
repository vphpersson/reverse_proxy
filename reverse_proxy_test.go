package main

import (
	"crypto/tls"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestSetForwardedHeaders(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		host            string
		remoteAddr      string
		tlsState        *tls.ConnectionState
		inboundHeader   http.Header
		expectedHeaders map[string]string
		unsetHeaders    []string
	}{
		{
			name:       "ipv4",
			host:       "example.com",
			remoteAddr: "192.0.2.10:54321",
			expectedHeaders: map[string]string{
				"Forwarded":         "for=192.0.2.10;proto=http;host=example.com",
				"X-Forwarded-For":   "192.0.2.10",
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host":  "example.com",
			},
		},
		{
			// Per RFC 7239 an IPv6 address must be bracketed and quoted in
			// Forwarded, while X-Forwarded-For carries it bare.
			name:       "ipv6 is bracketed and quoted in forwarded only",
			host:       "example.com",
			remoteAddr: "[2001:db8::1]:54321",
			expectedHeaders: map[string]string{
				"Forwarded":       `for="[2001:db8::1]";proto=http;host=example.com`,
				"X-Forwarded-For": "2001:db8::1",
			},
		},
		{
			name:       "tls makes the protocol https",
			host:       "example.com",
			remoteAddr: "192.0.2.10:54321",
			tlsState:   &tls.ConnectionState{},
			expectedHeaders: map[string]string{
				"Forwarded":         "for=192.0.2.10;proto=https;host=example.com",
				"X-Forwarded-Proto": "https",
			},
		},
		{
			// SplitHostPort fails, so the address is used verbatim.
			name:       "remote address without a port",
			host:       "example.com",
			remoteAddr: "192.0.2.10",
			expectedHeaders: map[string]string{
				"Forwarded":       "for=192.0.2.10;proto=http;host=example.com",
				"X-Forwarded-For": "192.0.2.10",
			},
		},
		{
			name:       "no host leaves the host parts out",
			remoteAddr: "192.0.2.10:54321",
			expectedHeaders: map[string]string{
				"Forwarded": "for=192.0.2.10;proto=http",
			},
			unsetHeaders: []string{"X-Forwarded-Host"},
		},
		{
			// Whatever the client claimed must be replaced, never appended to.
			name:       "client supplied values are replaced",
			host:       "example.com",
			remoteAddr: "192.0.2.10:54321",
			inboundHeader: http.Header{
				"Forwarded":         []string{"for=10.0.0.1"},
				"X-Forwarded-For":   []string{"10.0.0.1"},
				"X-Forwarded-Proto": []string{"https"},
				"X-Forwarded-Host":  []string{"evil.example"},
			},
			expectedHeaders: map[string]string{
				"Forwarded":         "for=192.0.2.10;proto=http;host=example.com",
				"X-Forwarded-For":   "192.0.2.10",
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host":  "example.com",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			inboundHeader := testCase.inboundHeader
			if inboundHeader == nil {
				inboundHeader = http.Header{}
			}

			inbound := &http.Request{
				Header:     inboundHeader,
				Host:       testCase.host,
				RemoteAddr: testCase.remoteAddr,
				TLS:        testCase.tlsState,
			}
			outbound := &http.Request{Header: inboundHeader.Clone()}

			setForwardedHeaders(outbound, inbound)

			for header, expected := range testCase.expectedHeaders {
				if got := outbound.Header.Get(header); got != expected {
					t.Errorf("%s = %q, want %q", header, got, expected)
				}

				// A replaced header must hold exactly one value.
				if values := outbound.Header.Values(header); len(values) != 1 {
					t.Errorf("%s has %d values, want 1: %v", header, len(values), values)
				}
			}

			for _, header := range testCase.unsetHeaders {
				if got := outbound.Header.Get(header); got != "" {
					t.Errorf("%s should be unset, got %q", header, got)
				}
			}
		})
	}
}

// newTestProxy builds the proxy exactly as main does, so the test exercises the
// real Rewrite hook rather than a copy of it.
func newTestProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			inbound := proxyRequest.In
			outbound := proxyRequest.Out

			proxyRequest.SetURL(target)
			outbound.Host = inbound.Host

			setForwardedHeaders(outbound, inbound)
		},
	}
}

func TestProxyForwardedHeaders(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		inboundHost      string
		inboundForwarded string
		expectedHost     string
	}{
		{
			name:         "the client address appears once",
			inboundHost:  "vhost.example",
			expectedHost: "vhost.example",
		},
		{
			// Regression: with a Director, ReverseProxy appended the client
			// address to the one already set, sending it upstream twice.
			name:             "a client supplied value is dropped, not appended",
			inboundHost:      "vhost.example",
			inboundForwarded: "203.0.113.9",
			expectedHost:     "vhost.example",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var seenForwardedFor string
			var seenForwarded string
			var seenHost string

			upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				seenForwardedFor = request.Header.Get("X-Forwarded-For")
				seenForwarded = request.Header.Get("Forwarded")
				seenHost = request.Host
			}))
			defer upstream.Close()

			target, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatalf("parse upstream url: %v", err)
			}

			front := httptest.NewServer(newTestProxy(target))
			defer front.Close()

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, front.URL, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Host = testCase.inboundHost
			if testCase.inboundForwarded != "" {
				request.Header.Set("X-Forwarded-For", testCase.inboundForwarded)
			}

			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			defer func() {
				_ = response.Body.Close()
			}()

			if seenForwardedFor != "127.0.0.1" {
				t.Errorf("upstream saw X-Forwarded-For %q, want a single \"127.0.0.1\"", seenForwardedFor)
			}

			// The RFC 7239 header travels alongside the X-Forwarded-* ones.
			expectedForwarded := "for=127.0.0.1;proto=http;host=" + testCase.inboundHost
			if seenForwarded != expectedForwarded {
				t.Errorf("upstream saw Forwarded %q, want %q", seenForwarded, expectedForwarded)
			}

			// SetURL points Host at the upstream; the host the client asked for
			// has to survive for the upstream to route on it.
			if seenHost != testCase.expectedHost {
				t.Errorf("upstream saw Host %q, want %q", seenHost, testCase.expectedHost)
			}
		})
	}
}

func TestUpstreamConfigurationUnmarshal(t *testing.T) {
	t.Parallel()

	const data = `{
		"a.example": {"url": "http://backend-a:8080"},
		"b.example": {"url": "https://backend-b", "use_client_authentication": true},
		"c.example": {"url": "https://elsewhere.example", "redirect": true}
	}`

	var configurations map[string]*UpstreamConfiguration
	if err := json.Unmarshal([]byte(data), &configurations); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	testCases := []struct {
		name                         string
		host                         string
		expectedUrl                  string
		expectedClientAuthentication bool
		expectedRedirect             bool
	}{
		{name: "plain upstream", host: "a.example", expectedUrl: "http://backend-a:8080"},
		{name: "client authentication", host: "b.example", expectedUrl: "https://backend-b", expectedClientAuthentication: true},
		{name: "redirect", host: "c.example", expectedUrl: "https://elsewhere.example", expectedRedirect: true},
	}

	if len(configurations) != len(testCases) {
		t.Fatalf("got %d configurations, want %d", len(configurations), len(testCases))
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			configuration := configurations[testCase.host]
			if configuration == nil {
				t.Fatalf("no configuration for %s", testCase.host)
			}

			if configuration.Url != testCase.expectedUrl {
				t.Errorf("url = %q, want %q", configuration.Url, testCase.expectedUrl)
			}

			if configuration.UseClientAuthentication != testCase.expectedClientAuthentication {
				t.Errorf("use_client_authentication = %v, want %v", configuration.UseClientAuthentication, testCase.expectedClientAuthentication)
			}

			if configuration.Redirect != testCase.expectedRedirect {
				t.Errorf("redirect = %v, want %v", configuration.Redirect, testCase.expectedRedirect)
			}
		})
	}
}
