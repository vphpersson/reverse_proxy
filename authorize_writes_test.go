package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

// clientState builds the connection state RequireAndVerifyClientCert would
// leave on a request whose peer presented a certificate with commonName.
func clientState(commonName string) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: commonName}}},
	}
}

func TestAuthorizeWrites(t *testing.T) {
	t.Parallel()

	allowed := []string{"capa_registry"}

	testCases := []struct {
		name               string
		allowedCommonNames []string
		method             string
		connectionState    *tls.ConnectionState
		expectedForwarded  bool
		expectedStatusCode int
	}{
		{
			name:               "read from an allowed name",
			allowedCommonNames: allowed,
			method:             http.MethodGet,
			connectionState:    clientState("capa_registry"),
			expectedForwarded:  true,
			expectedStatusCode: http.StatusOK,
		},
		{
			// The point of the feature: glory pulls, and pulling is GET/HEAD.
			name:               "read from a name that may not write",
			allowedCommonNames: allowed,
			method:             http.MethodGet,
			connectionState:    clientState("glory_registry"),
			expectedForwarded:  true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "head from a name that may not write",
			allowedCommonNames: allowed,
			method:             http.MethodHead,
			connectionState:    clientState("glory_registry"),
			expectedForwarded:  true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "write from an allowed name",
			allowedCommonNames: allowed,
			method:             http.MethodPut,
			connectionState:    clientState("capa_registry"),
			expectedForwarded:  true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "write from a disallowed name",
			allowedCommonNames: allowed,
			method:             http.MethodPut,
			connectionState:    clientState("glory_registry"),
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			// A registry push is POST, then PATCH, then PUT; blocking only one
			// of them would leave the upload half-open rather than refused.
			name:               "post from a disallowed name",
			allowedCommonNames: allowed,
			method:             http.MethodPost,
			connectionState:    clientState("glory_registry"),
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "patch from a disallowed name",
			allowedCommonNames: allowed,
			method:             http.MethodPatch,
			connectionState:    clientState("glory_registry"),
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "delete from a disallowed name",
			allowedCommonNames: allowed,
			method:             http.MethodDelete,
			connectionState:    clientState("glory_registry"),
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "write without tls",
			allowedCommonNames: allowed,
			method:             http.MethodPut,
			connectionState:    nil,
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "write with tls but no peer certificate",
			allowedCommonNames: allowed,
			method:             http.MethodPut,
			connectionState:    &tls.ConnectionState{},
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "empty allow list refuses every write",
			allowedCommonNames: nil,
			method:             http.MethodPut,
			connectionState:    clientState("capa_registry"),
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "empty allow list still permits reads",
			allowedCommonNames: nil,
			method:             http.MethodGet,
			connectionState:    clientState("capa_registry"),
			expectedForwarded:  true,
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var forwarded bool
			next := http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
				forwarded = true
				responseWriter.WriteHeader(http.StatusOK)
			})

			request := httptest.NewRequestWithContext(
				t.Context(),
				testCase.method,
				"/v2/thing/blobs/uploads/",
				nil,
			)
			request.TLS = testCase.connectionState

			recorder := httptest.NewRecorder()
			authorizeWrites(next, testCase.allowedCommonNames).ServeHTTP(recorder, request)

			if forwarded != testCase.expectedForwarded {
				t.Errorf("%s: forwarded = %v, want %v", testCase.name, forwarded, testCase.expectedForwarded)
			}

			if recorder.Code != testCase.expectedStatusCode {
				t.Errorf("%s: status = %d, want %d", testCase.name, recorder.Code, testCase.expectedStatusCode)
			}
		})
	}
}

func TestAuthorizeClients(t *testing.T) {
	t.Parallel()

	allowed := []string{"capa_browser"}

	testCases := []struct {
		name               string
		allowedCommonNames []string
		method             string
		connectionState    *tls.ConnectionState
		expectedForwarded  bool
		expectedStatusCode int
	}{
		{
			name:               "allowed name reads",
			allowedCommonNames: allowed,
			method:             http.MethodGet,
			connectionState:    clientState("capa_browser"),
			expectedForwarded:  true,
			expectedStatusCode: http.StatusOK,
		},
		{
			// Kibana searches with POST, which is why the write rule cannot
			// stand in for this one.
			name:               "allowed name posts",
			allowedCommonNames: allowed,
			method:             http.MethodPost,
			connectionState:    clientState("capa_browser"),
			expectedForwarded:  true,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "another machine in the fleet is refused a read",
			allowedCommonNames: allowed,
			method:             http.MethodGet,
			connectionState:    clientState("glory_registry"),
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "another machine in the fleet is refused a post",
			allowedCommonNames: allowed,
			method:             http.MethodPost,
			connectionState:    clientState("glory_registry"),
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "no tls",
			allowedCommonNames: allowed,
			method:             http.MethodGet,
			connectionState:    nil,
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "tls without a peer certificate",
			allowedCommonNames: allowed,
			method:             http.MethodGet,
			connectionState:    &tls.ConnectionState{},
			expectedForwarded:  false,
			expectedStatusCode: http.StatusForbidden,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var forwarded bool
			next := http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
				forwarded = true
				responseWriter.WriteHeader(http.StatusOK)
			})

			request := httptest.NewRequestWithContext(t.Context(), testCase.method, "/app/home", nil)
			request.TLS = testCase.connectionState

			recorder := httptest.NewRecorder()
			authorizeClients(next, testCase.allowedCommonNames).ServeHTTP(recorder, request)

			if forwarded != testCase.expectedForwarded {
				t.Errorf("%s: forwarded = %v, want %v", testCase.name, forwarded, testCase.expectedForwarded)
			}

			if recorder.Code != testCase.expectedStatusCode {
				t.Errorf("%s: status = %d, want %d", testCase.name, recorder.Code, testCase.expectedStatusCode)
			}
		})
	}
}
