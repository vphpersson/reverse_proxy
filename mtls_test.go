package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// authority is a certificate authority the tests issue from.
type authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pemBytes    []byte
}

func newAuthority(t *testing.T, name string) *authority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	return &authority{
		certificate: certificate,
		key:         key,
		pemBytes:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issue returns a leaf certificate signed by the authority.
func (ca *authority) issue(t *testing.T, commonName string, serverName string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if serverName != "" {
		template.DNSNames = []string{serverName}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: mustParse(t, der)}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return certificate
}

func writeCaFile(t *testing.T, ca *authority) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca.pemBytes, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}

	return path
}

func TestNewHostTlsConfig(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "test ca")
	caPath := writeCaFile(t, ca)

	emptyPath := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(emptyPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write empty ca file: %v", err)
	}

	testCases := []struct {
		name               string
		configuration      *UpstreamConfiguration
		expectErr          bool
		expectedClientAuth tls.ClientAuthType
		expectPinnedPool   bool
	}{
		{
			name:               "no client authentication",
			configuration:      &UpstreamConfiguration{Url: "http://upstream"},
			expectedClientAuth: tls.NoClientCert,
		},
		{
			name:               "client authentication with a ca file pins to it",
			configuration:      &UpstreamConfiguration{Url: "https://upstream", UseClientAuthentication: true, ClientCaFilePath: caPath},
			expectedClientAuth: tls.RequireAndVerifyClientCert,
			expectPinnedPool:   true,
		},
		{
			// Without this the system roots are used, which authenticates nothing.
			name:          "client authentication without a ca file is refused",
			configuration: &UpstreamConfiguration{Url: "https://upstream", UseClientAuthentication: true},
			expectErr:     true,
		},
		{
			name:          "a ca file holding no certificates is refused",
			configuration: &UpstreamConfiguration{Url: "https://upstream", UseClientAuthentication: true, ClientCaFilePath: emptyPath},
			expectErr:     true,
		},
		{
			name:          "a missing ca file is refused",
			configuration: &UpstreamConfiguration{Url: "https://upstream", UseClientAuthentication: true, ClientCaFilePath: "/nonexistent/ca.pem"},
			expectErr:     true,
		},
		{
			name:          "nil configuration",
			configuration: nil,
			expectErr:     true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			tlsConfig, err := newHostTlsConfig(tls.Certificate{}, testCase.configuration)

			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if tlsConfig.ClientAuth != testCase.expectedClientAuth {
				t.Errorf("ClientAuth = %v, want %v", tlsConfig.ClientAuth, testCase.expectedClientAuth)
			}

			// A nil pool is what made the old behaviour fall back to the system roots.
			if testCase.expectPinnedPool && tlsConfig.ClientCAs == nil {
				t.Error("expected ClientCAs to be pinned, got nil")
			}
			if !testCase.expectPinnedPool && tlsConfig.ClientCAs != nil {
				t.Error("expected no ClientCAs")
			}
		})
	}
}

func TestClientAuthenticationAcceptsOnlyThePinnedAuthority(t *testing.T) {
	t.Parallel()

	pinned := newAuthority(t, "pinned ca")
	other := newAuthority(t, "some other ca")

	serverCertificate := pinned.issue(t, "server", "example.test")

	tlsConfig, err := newHostTlsConfig(
		serverCertificate,
		&UpstreamConfiguration{
			Url:                     "http://upstream",
			UseClientAuthentication: true,
			ClientCaFilePath:        writeCaFile(t, pinned),
		},
	)
	if err != nil {
		t.Fatalf("new host tls config: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = tlsConfig
	server.StartTLS()
	// Not defer: the subtests below are parallel, so they run after this
	// function returns. A cleanup runs after they finish, a defer before.
	t.Cleanup(server.Close)

	// The client must trust the server's certificate for the handshake to reach
	// the point where the client's own certificate is judged.
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(pinned.certificate)

	testCases := []struct {
		name              string
		clientCertificate *tls.Certificate
		expectAccepted    bool
	}{
		{
			name:              "a certificate from the pinned authority is accepted",
			clientCertificate: certificatePointer(pinned.issue(t, "client", "")),
			expectAccepted:    true,
		},
		{
			// This is the case the old configuration would have let through, since
			// verification fell back to the system roots.
			name:              "a certificate from another authority is rejected",
			clientCertificate: certificatePointer(other.issue(t, "client", "")),
			expectAccepted:    false,
		},
		{
			name:              "no certificate at all is rejected",
			clientCertificate: nil,
			expectAccepted:    false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			clientTlsConfig := &tls.Config{RootCAs: serverRoots, ServerName: "example.test"}
			if testCase.clientCertificate != nil {
				clientTlsConfig.Certificates = []tls.Certificate{*testCase.clientCertificate}
			}

			client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTlsConfig}}

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}

			response, err := client.Do(request)
			if err == nil {
				defer func() {
					_ = response.Body.Close()
				}()
			}

			accepted := err == nil
			if accepted != testCase.expectAccepted {
				t.Errorf("accepted = %v, want %v (err: %v)", accepted, testCase.expectAccepted, err)
			}
		})
	}
}

func certificatePointer(certificate tls.Certificate) *tls.Certificate {
	return &certificate
}
