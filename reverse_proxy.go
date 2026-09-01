package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	argumentParser "github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	argumentParserErrors "github.com/altshiftab/utils_go/pkg/cli/argument_parser/errors"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftEnv "github.com/altshiftab/utils_go/pkg/env"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftMux "github.com/altshiftab/utils_go/pkg/http/mux"
	altshiftForwardedHeaders "github.com/altshiftab/utils_go/pkg/http/mux/types/forwarded_headers"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftContextLogger "github.com/altshiftab/utils_go/pkg/log/context_logger"
	altshiftErrorLogger "github.com/altshiftab/utils_go/pkg/log/error_logger"
	schemaLog "github.com/altshiftab/utils_go/pkg/schema/log"
)

const programName = "reverse_proxy"

// errNoUpstreamConfiguration fails the handshake for a server name that is not
// configured, rather than serving it something it did not ask for.
var errNoUpstreamConfiguration = errors.New("no upstream configuration for the server name")

const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 60 * time.Second
	idleTimeout       = 120 * time.Second
)

type UpstreamConfiguration struct {
	Url                     string `json:"url,omitzero"`
	UseClientAuthentication bool   `json:"use_client_authentication,omitzero"`
	// ClientCaFilePath names the PEM bundle a client certificate must chain to.
	// It is required whenever UseClientAuthentication is set: without it Go
	// verifies against the system roots, which would accept any certificate
	// issued by any public authority.
	ClientCaFilePath string `json:"client_ca_file_path,omitzero"`
	Redirect         bool   `json:"redirect,omitzero"`
	// StreamRequestBody marks an upstream whose clients can hold a request body
	// open for longer than readTimeout allows, which a whole-request deadline
	// cannot express. It clears that deadline for the vhost; see
	// streamRequestBody.
	StreamRequestBody bool `json:"stream_request_body,omitzero"`
}

// streamRequestBody returns a handler that clears the server's whole-request
// read deadline for the hosts in streamHosts before delegating.
//
// http.Server.ReadTimeout bounds reading the entire request, body included, so a
// client that streams one long-lived body can never satisfy it.
// systemd-journal-upload does exactly that: it holds a single chunked POST open
// for as long as it has entries, so the 60s readTimeout cut every upload at 60s
// on the dot. Because the request never completed, its cursor never advanced and
// each retry replayed the same backlog from the start -- roughly 2GB/hour of
// duplicates into journal-remote, whose vacuuming then evicted the other hosts'
// logs from the retention window.
//
// This must wrap the *server's* handler, not an individual vhost's:
// http.ResponseController reaches the connection by unwrapping the
// ResponseWriter, and VhostMux hands its specifications a wrapper with no
// Unwrap method, so from inside a vhost every call fails with "feature not
// supported" and the deadline silently stays put. Out here the writer is still
// net/http's own. The host is resolved with the same helper VhostMux routes on
// so the two cannot disagree about which vhost a request belongs to.
//
// Clearing per request keeps ReadTimeout in force for every other vhost.
func streamRequestBody(
	handler http.Handler,
	streamHosts map[string]struct{},
	trustForwardedHost bool,
	logError func(string, error, ...any),
) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		host := altshiftForwardedHeaders.Host(request, trustForwardedHost)

		if _, ok := streamHosts[host]; ok {
			if err := http.NewResponseController(responseWriter).SetReadDeadline(time.Time{}); err != nil {
				// Not fatal: the request is still served, only with the deadline
				// the server set for it.
				logError(
					"An error occurred when clearing the request read deadline.",
					altshiftErrors.NewWithTrace(fmt.Errorf("response controller set read deadline: %w", err)),
					host,
				)
			}
		}

		handler.ServeHTTP(responseWriter, request)
	})
}

// setForwardedHeaders populates the Forwarded (RFC 7239) and X-Forwarded-*
// headers on outbound from what inbound says about the client. They are set
// rather than appended: this is the first hop, so whatever the client claimed
// is not to be trusted or carried forward. The caller must ensure that both
// requests and outbound.Header are non-nil.
func setForwardedHeaders(outbound *http.Request, inbound *http.Request) {
	proto := "http"
	if inbound.TLS != nil {
		proto = "https"
	}

	clientIp, _, err := net.SplitHostPort(inbound.RemoteAddr)
	if err != nil {
		clientIp = inbound.RemoteAddr
	}

	requestHost := inbound.Host

	// Per RFC 7239, IPv6 addresses in the Forwarded header must be bracketed
	// and quoted (e.g. for="[2001:db8::1]").
	forwardedFor := clientIp
	if ip := net.ParseIP(clientIp); ip != nil && ip.To4() == nil {
		forwardedFor = fmt.Sprintf("%q", "["+clientIp+"]")
	}

	forwardedString := fmt.Sprintf("for=%s;proto=%s", forwardedFor, proto)
	if requestHost != "" {
		forwardedString += fmt.Sprintf(";host=%s", requestHost)
	}

	requestHeader := outbound.Header
	requestHeader.Set("Forwarded", forwardedString)
	requestHeader.Set("X-Forwarded-For", clientIp)
	requestHeader.Set("X-Forwarded-Proto", proto)

	if requestHost != "" {
		requestHeader.Set("X-Forwarded-Host", requestHost)
	}
}

type CliConfig struct {
	ServerAddress       string
	CertificateFilePath string
	KeyFilePath         string
	ConfigFilePath      string
	Verbose             bool
}

func parseArguments() (*CliConfig, error) {
	config := &CliConfig{
		// The environment provides the defaults; an argument overrides one.
		ServerAddress:       altshiftEnv.GetEnvWithDefault("SERVER_ADDRESS", ":443"),
		CertificateFilePath: altshiftEnv.GetEnvWithDefault("CERTIFICATE_FILE_PATH", ""),
		KeyFilePath:         altshiftEnv.GetEnvWithDefault("CERTIFICATE_KEY_PATH", ""),
		ConfigFilePath:      altshiftEnv.GetEnvWithDefault("CONFIG_PATH", "/etc/reverse_proxy/config.json"),
	}

	parser := &argumentParser.Parser{
		ProgramName: programName,
		Description: "Serve configured hosts over TLS, proxying or redirecting each to its upstream.",
		Options: []option.Option{
			option.NewStringOption('a', "addr", "The address to serve on.", false, &config.ServerAddress),
			option.NewStringOption('c', "cert", "Path to the TLS certificate file.", false, &config.CertificateFilePath),
			option.NewStringOption('k', "key", "Path to the TLS key file.", false, &config.KeyFilePath),
			option.NewStringOption(0, "config", "Path to the configuration file.", false, &config.ConfigFilePath),
			option.NewBoolOption('v', "verbose", "Log at debug level.", false, &config.Verbose),
		},
	}

	if err := parser.Validate(); err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("parser validate: %w", err))
	}

	if err := parser.Parse(); err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("parse: %w", err))
	}

	return config, nil
}

// newHostTlsConfig builds the TLS configuration a host is served with. When the
// host asks for client authentication, the certificates offered are pinned to
// the configured authority: with ClientCAs left unset Go verifies against the
// system roots instead, which accepts any certificate issued by any public
// authority and so authenticates nothing.
func newHostTlsConfig(
	certificate tls.Certificate,
	upstreamConfiguration *UpstreamConfiguration,
) (*tls.Config, error) {
	if upstreamConfiguration == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("upstream configuration"))
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}}

	if !upstreamConfiguration.UseClientAuthentication {
		return tlsConfig, nil
	}

	clientCaFilePath := upstreamConfiguration.ClientCaFilePath
	if clientCaFilePath == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("client ca file path"))
	}

	clientCaData, err := os.ReadFile(clientCaFilePath)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("os read file (client ca): %w", err),
			clientCaFilePath,
		)
	}

	clientCaPool := x509.NewCertPool()
	if !clientCaPool.AppendCertsFromPEM(clientCaData) {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: no certificates in the client ca file", altshiftErrors.ErrParseError),
			clientCaFilePath,
		)
	}

	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = clientCaPool

	return tlsConfig, nil
}

func main() {
	config, err := parseArguments()
	if err != nil {
		// Help is an answer to an explicit request, not a failure.
		if errors.Is(err, argumentParserErrors.ErrHelp) {
			return
		}

		fmt.Fprintf(os.Stderr, "%s: %v\n", programName, err)
		os.Exit(1)
	}

	logLevel := slog.LevelInfo
	if config.Verbose {
		logLevel = slog.LevelDebug
	}

	httpContextExtractor := &http_context_extractor.Extractor{}
	makeLogger := func(eventAttrs ...any) *altshiftErrorLogger.Logger {
		return &altshiftErrorLogger.Logger{
			Logger: altshiftContextLogger.New(
				slog.NewJSONHandler(
					os.Stdout,
					&slog.HandlerOptions{Level: logLevel, ReplaceAttr: schemaLog.ReplaceAttr},
				),
				&altshiftLog.ErrorContextExtractor{
					ContextExtractors: []altshiftLog.ContextExtractor{
						httpContextExtractor,
					},
				},
				httpContextExtractor,
			).With(slog.Group("event", eventAttrs...)),
		}
	}

	logger := makeLogger(slog.String("dataset", "reverse_proxy"))
	slog.SetDefault(logger.Logger)

	logFatal := func(reason string, err error, input ...any) {
		l := makeLogger(slog.String("dataset", "reverse_proxy"), slog.String("reason", reason))
		l.Fatal(err.Error(), err, input...)
	}

	logError := func(reason string, err error, input ...any) {
		l := makeLogger(slog.String("dataset", "reverse_proxy"), slog.String("reason", reason))
		l.Error(err.Error(), err, input...)
	}

	serverAddress := config.ServerAddress
	if serverAddress == "" {
		logFatal(
			"Empty server address.",
			altshiftErrors.NewWithTrace(empty_error.New("server address")),
		)
	}

	certificateFilePath := config.CertificateFilePath
	if certificateFilePath == "" {
		logFatal(
			"Empty certificate file path.",
			altshiftErrors.NewWithTrace(empty_error.New("certificate file path")),
		)
	}

	keyFilePath := config.KeyFilePath
	if keyFilePath == "" {
		logFatal(
			"Empty key file path.",
			altshiftErrors.NewWithTrace(empty_error.New("key file path")),
		)
	}

	configFilePath := config.ConfigFilePath
	if configFilePath == "" {
		logFatal(
			"Empty config path.",
			altshiftErrors.NewWithTrace(empty_error.New("config file path")),
		)
	}

	// Read the configuration file.

	configData, err := os.ReadFile(configFilePath)
	if err != nil {
		logFatal(
			"An error occurred when reading the configuration file.",
			altshiftErrors.NewWithTrace(fmt.Errorf("os read file (config): %w", err)),
			configFilePath,
		)
	}

	var hostToUpstreamConfiguration map[string]*UpstreamConfiguration
	if err := json.Unmarshal(configData, &hostToUpstreamConfiguration); err != nil {
		logFatal(
			"An error occurred when decoding the configuration file.",
			altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (config): %w", err)),
			configData,
		)
	}
	if len(hostToUpstreamConfiguration) == 0 {
		logger.Warn("The host to upstream configuration is empty.")
	}

	// Read the certificate material.

	certificateData, err := os.ReadFile(certificateFilePath)
	if err != nil {
		logFatal(
			"An error occurred when reading the certificate file.",
			altshiftErrors.NewWithTrace(fmt.Errorf("os read file (certificate): %w", err), certificateFilePath),
		)
	}
	if len(certificateData) == 0 {
		logFatal(
			"Empty certificate data.",
			altshiftErrors.NewWithTrace(empty_error.New("certificate data")),
		)
	}

	keyData, err := os.ReadFile(keyFilePath)
	if err != nil {
		logFatal(
			"An error occurred when reading the key file.",
			altshiftErrors.NewWithTrace(fmt.Errorf("os read file (key): %w", err), keyFilePath),
		)
	}
	if len(keyData) == 0 {
		logFatal(
			"Empty key data.",
			altshiftErrors.NewWithTrace(empty_error.New("key data")),
		)
	}

	certificate, err := tls.X509KeyPair(certificateData, keyData)
	if err != nil {
		logFatal(
			"An error occurred when parsing the certificate and key.",
			altshiftErrors.NewWithTrace(fmt.Errorf("tls x509 key pair: %w", err)),
		)
	}

	// Make the Vhost mux configuration.

	hostToSpecification := make(map[string]*altshiftMux.VhostMuxSpecification)
	hostToTlsConfig := make(map[string]*tls.Config)
	streamRequestBodyHosts := make(map[string]struct{})

	for host, upstreamConfiguration := range hostToUpstreamConfiguration {
		if upstreamConfiguration == nil {
			logFatal(
				"Empty upstream configuration.",
				altshiftErrors.NewWithTrace(nil_error.New("upstream configuration")),
			)
			// logFatal exits; this makes that plain to the reader and the compiler.
			continue
		}

		if upstreamConfiguration.StreamRequestBody {
			streamRequestBodyHosts[host] = struct{}{}
		}

		upstreamUrl := upstreamConfiguration.Url
		if upstreamUrl == "" {
			logFatal(
				"Empty upstream URL.",
				altshiftErrors.NewWithTrace(empty_error.New("upstream url")),
			)
		}

		target, err := url.Parse(upstreamUrl)
		if err != nil {
			logFatal(
				"An error occurred when parsing an upstream URL.",
				altshiftErrors.NewWithTrace(fmt.Errorf("url parse: %w", err)),
				upstreamUrl,
			)
		}

		// The TLS configuration is settled here rather than per handshake, so a
		// misconfiguration is a startup failure rather than a runtime one.
		hostTlsConfig, err := newHostTlsConfig(certificate, upstreamConfiguration)
		if err != nil {
			logFatal(
				"An error occurred when building a host TLS configuration.",
				altshiftErrors.New(fmt.Errorf("new host tls config: %w", err), host),
			)
			continue
		}

		hostToTlsConfig[host] = hostTlsConfig

		var specification *altshiftMux.VhostMuxSpecification

		if upstreamConfiguration.Redirect {
			specification = &altshiftMux.VhostMuxSpecification{RedirectTo: upstreamUrl}
		} else {
			// Rewrite rather than Director: ReverseProxy appends the client
			// address to X-Forwarded-For itself when a Director is used, which
			// duplicated the address this already set. Rewrite leaves the header
			// entirely to this function.
			proxy := &httputil.ReverseProxy{
				Rewrite: func(proxyRequest *httputil.ProxyRequest) {
					if proxyRequest == nil {
						logError(
							"Empty proxy request.",
							altshiftErrors.NewWithTrace(nil_error.New("proxy request")),
						)
						return
					}

					inbound := proxyRequest.In
					outbound := proxyRequest.Out
					if inbound == nil || outbound == nil {
						logError(
							"Empty HTTP request.",
							altshiftErrors.NewWithTrace(nil_error.New("http request")),
						)
						return
					}

					proxyRequest.SetURL(target)
					// SetURL points Host at the upstream. The upstream is addressed
					// by name here, so the host the client asked for has to be put
					// back for it to route on.
					outbound.Host = inbound.Host

					if outbound.Header == nil {
						logError(
							"Empty HTTP request header.",
							altshiftErrors.NewWithTrace(nil_error.New("http request header")),
						)
						return
					}

					setForwardedHeaders(outbound, inbound)
				},
			}

			proxyLogger := makeLogger(
				slog.String("dataset", "reverse_proxy"),
				slog.String("reason", "A proxy error occurred."),
			)
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				proxyLogger.Error(
					err.Error(),
					altshiftErrors.NewWithTrace(fmt.Errorf("proxy: %w", err)),
				)
				w.WriteHeader(http.StatusBadGateway)
			}

			specification = &altshiftMux.VhostMuxSpecification{Mux: proxy}
		}

		hostToSpecification[host] = specification
	}

	vhostMux := &altshiftMux.VhostMux{HostToSpecification: hostToSpecification}
	if config.Verbose {
		vhostMux.DoneCallback = func(ctx context.Context) {
			slog.DebugContext(ctx, "An HTTP response was served.")
		}
	}

	var rootHandler http.Handler = vhostMux
	if len(streamRequestBodyHosts) != 0 {
		rootHandler = streamRequestBody(
			rootHandler,
			streamRequestBodyHosts,
			vhostMux.TrustForwardedHost,
			logError,
		)
	}

	server := &http.Server{
		Addr:    serverAddress,
		Handler: rootHandler,
		// Without these a client can hold a connection, or a request, open for
		// as long as it likes. WriteTimeout is left unset: a proxied response
		// takes as long as its upstream does, and ReadTimeout is lifted per host
		// by streamRequestBody for an upstream whose clients stream one.
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		TLSConfig: &tls.Config{
			GetConfigForClient: func(clientHelloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
				if clientHelloInfo == nil {
					return nil, altshiftErrors.NewWithTrace(nil_error.New("client hello info"))
				}

				serverName := clientHelloInfo.ServerName

				hostTlsConfig, ok := hostToTlsConfig[serverName]
				if !ok {
					// Fail the TLS handshake when there is no matching configuration for the server name.
					return nil, altshiftErrors.NewWithTrace(
						fmt.Errorf("%w: %q", errNoUpstreamConfiguration, serverName),
						serverName,
					)
				}

				return hostTlsConfig, nil
			},
		},
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		logFatal(
			"An error occurred when listening and serving.",
			altshiftErrors.NewWithTrace(fmt.Errorf("http listen and serve: %w", err)),
		)
	}
}
