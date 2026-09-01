package main

import (
	"crypto/tls"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"
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
		"c.example": {"url": "https://elsewhere.example", "redirect": true},
		"d.example": {"url": "http://backend-d:9090", "stream_request_body": true}
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
		expectedStreamRequestBody    bool
	}{
		{name: "plain upstream", host: "a.example", expectedUrl: "http://backend-a:8080"},
		{name: "client authentication", host: "b.example", expectedUrl: "https://backend-b", expectedClientAuthentication: true},
		{name: "redirect", host: "c.example", expectedUrl: "https://elsewhere.example", expectedRedirect: true},
		// The tag name is what config.json has to spell; a typo here would
		// silently leave the upstream on the default timeout and pooling.
		{name: "stream request body", host: "d.example", expectedUrl: "http://backend-d:9090", expectedStreamRequestBody: true},
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

			if configuration.StreamRequestBody != testCase.expectedStreamRequestBody {
				t.Errorf("stream_request_body = %v, want %v", configuration.StreamRequestBody, testCase.expectedStreamRequestBody)
			}
		})
	}
}

// TestNoKeepAliveTransportOpensAFreshConnection counts distinct upstream
// connections across sequential requests. The pooled default reuses one, which
// is what races journal-remote's idle close and surfaces as a 502; the returned
// transport must not.
func TestNoKeepAliveTransportOpensAFreshConnection(t *testing.T) {
	t.Parallel()

	const requestCount = 3

	testCases := []struct {
		name                    string
		transport               http.RoundTripper
		expectedConnectionCount int
	}{
		{
			name:                    "no keep alive opens one connection per request",
			transport:               newNoKeepAliveTransport(),
			expectedConnectionCount: requestCount,
		},
		{
			name:                    "the pooled default reuses a single connection",
			transport:               http.DefaultTransport,
			expectedConnectionCount: 1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var mutex sync.Mutex
			remoteAddresses := make(map[string]struct{})

			server := httptest.NewServer(http.HandlerFunc(
				func(_ http.ResponseWriter, request *http.Request) {
					mutex.Lock()
					remoteAddresses[request.RemoteAddr] = struct{}{}
					mutex.Unlock()
				},
			))
			defer server.Close()

			client := &http.Client{Transport: testCase.transport}
			for range requestCount {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
				if err != nil {
					t.Fatalf("%s: new request: %v", testCase.name, err)
				}

				response, err := client.Do(request)
				if err != nil {
					t.Fatalf("%s: do: %v", testCase.name, err)
				}
				// The body must be drained and closed for a pooled connection to
				// be returned to the pool, or the comparison case proves nothing.
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					t.Fatalf("%s: drain body: %v", testCase.name, err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatalf("%s: close body: %v", testCase.name, err)
				}
			}

			if len(remoteAddresses) != testCase.expectedConnectionCount {
				t.Errorf(
					"%s: upstream saw %d distinct connections, want %d",
					testCase.name,
					len(remoteAddresses),
					testCase.expectedConnectionCount,
				)
			}
		})
	}
}

// TestStreamRequestBody drives a real server whose ReadTimeout is shorter than
// the body takes to arrive, which is the shape that cut every journal-upload at
// 60s. The unconfigured case is what every vhost still gets, so together they
// pin both halves: the deadline is lifted where it is asked for and nowhere
// else.
func TestStreamRequestBody(t *testing.T) {
	t.Parallel()

	const (
		serverReadTimeout = 250 * time.Millisecond
		chunkCount        = 4
		chunkDelay        = 200 * time.Millisecond
		chunk             = "0123456789"
	)

	testCases := []struct {
		name string
		// configured makes the request's own host one of streamHosts, as
		// upload-logs.home.arpa is; otherwise the set names a different host and
		// the request must keep the deadline the server gave it.
		configured      bool
		expectReadError bool
	}{
		{
			name:       "configured host outlives the read timeout",
			configured: true,
		},
		{
			name:            "unconfigured host keeps the read timeout",
			expectReadError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			type readResult struct {
				byteCount int
				err       error
			}
			readResults := make(chan readResult, 1)

			var handler http.Handler = http.HandlerFunc(
				func(_ http.ResponseWriter, request *http.Request) {
					body, err := io.ReadAll(request.Body)
					readResults <- readResult{byteCount: len(body), err: err}
				},
			)

			// httptest serves on a loopback address, so that is the host the
			// request carries and the one the wrapper has to match on.
			streamHost := "127.0.0.1"
			if !testCase.configured {
				streamHost = "some-other-host.invalid"
			}

			loggedErrors := make(chan error, 8)
			handler = streamRequestBody(
				handler,
				map[string]struct{}{streamHost: {}},
				false,
				func(_ string, err error, _ ...any) { loggedErrors <- err },
			)

			server := httptest.NewUnstartedServer(handler)
			server.Config.ReadTimeout = serverReadTimeout
			server.Start()
			defer server.Close()

			pipeReader, pipeWriter := io.Pipe()
			go func() {
				for range chunkCount {
					time.Sleep(chunkDelay)
					if _, err := io.WriteString(pipeWriter, chunk); err != nil {
						_ = pipeWriter.CloseWithError(err)
						return
					}
				}
				_ = pipeWriter.Close()
			}()

			request, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				server.URL,
				pipeReader,
			)
			if err != nil {
				t.Fatalf("%s: new request: %v", testCase.name, err)
			}

			if response, err := server.Client().Do(request); err == nil {
				_ = response.Body.Close()
			}

			select {
			case result := <-readResults:
				switch {
				case testCase.expectReadError && result.err == nil:
					t.Errorf(
						"%s: expected a body read error, read %d bytes without one",
						testCase.name,
						result.byteCount,
					)
				case !testCase.expectReadError && result.err != nil:
					t.Errorf("%s: unexpected body read error: %v", testCase.name, result.err)
				case !testCase.expectReadError && result.byteCount != chunkCount*len(chunk):
					t.Errorf(
						"%s: read %d bytes, want %d",
						testCase.name,
						result.byteCount,
						chunkCount*len(chunk),
					)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: the handler was never reached", testCase.name)
			}

			close(loggedErrors)
			for err := range loggedErrors {
				t.Errorf("%s: clearing the read deadline logged an error: %v", testCase.name, err)
			}
		})
	}
}
