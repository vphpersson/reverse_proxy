package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	motmedelEnv "github.com/Motmedel/utils_go/pkg/env"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelHttpErrors "github.com/Motmedel/utils_go/pkg/http/errors"
	motmedelMux "github.com/Motmedel/utils_go/pkg/http/mux"
	"github.com/Motmedel/utils_go/pkg/http/types/http_context_extractor"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelContextLogger "github.com/Motmedel/utils_go/pkg/log/context_logger"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	schemaLog "github.com/Motmedel/utils_go/pkg/schema/log"
)

type UpstreamConfiguration struct {
	Url                     string `json:"url,omitempty"`
	UseClientAuthentication bool   `json:"use_client_authentication,omitempty"`
	Redirect                bool   `json:"redirect,omitempty"`
}

// setForwardedHeaders populates the Forwarded (RFC 7239) and X-Forwarded-*
// headers on request based on its RemoteAddr, Host and TLS state. The caller
// must ensure that request and request.Header are non-nil.
func setForwardedHeaders(request *http.Request) {
	proto := "http"
	if request.TLS != nil {
		proto = "https"
	}

	clientIp, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		clientIp = request.RemoteAddr
	}

	requestHost := request.Host

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

	requestHeader := request.Header
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

func parseFlags() *CliConfig {
	config := &CliConfig{}

	flag.StringVar(
		&config.ServerAddress,
		"addr",
		motmedelEnv.GetEnvWithDefault("SERVER_ADDRESS", ":443"),
		"HTTP server address",
	)

	flag.StringVar(
		&config.CertificateFilePath,
		"cert",
		motmedelEnv.GetEnvWithDefault("CERTIFICATE_FILE_PATH", ""),
		"Path to TLS certificate file",
	)

	flag.StringVar(
		&config.KeyFilePath,
		"key",
		motmedelEnv.GetEnvWithDefault("CERTIFICATE_KEY_PATH", ""),
		"Path to TLS key file",
	)

	flag.StringVar(
		&config.ConfigFilePath,
		"config",
		motmedelEnv.GetEnvWithDefault("CONFIG_PATH", "/etc/reverse_proxy/config.json"),
		"Path to the configuration file",
	)

	flag.BoolVar(
		&config.Verbose,
		"verbose",
		false,
		"Enable verbose (debug-level) logging",
	)

	flag.Parse()

	return config
}

func main() {
	config := parseFlags()

	logLevel := slog.LevelInfo
	if config.Verbose {
		logLevel = slog.LevelDebug
	}

	httpContextExtractor := &http_context_extractor.Extractor{}
	makeLogger := func(eventAttrs ...any) *motmedelErrorLogger.Logger {
		return &motmedelErrorLogger.Logger{
			Logger: motmedelContextLogger.New(
				slog.NewJSONHandler(
					os.Stdout,
					&slog.HandlerOptions{Level: logLevel, ReplaceAttr: schemaLog.ReplaceAttr},
				),
				&motmedelLog.ErrorContextExtractor{
					ContextExtractors: []motmedelLog.ContextExtractor{
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
			motmedelErrors.NewWithTrace(empty_error.New("server address")),
		)
	}

	certificateFilePath := config.CertificateFilePath
	if certificateFilePath == "" {
		logFatal(
			"Empty certificate file path.",
			motmedelErrors.NewWithTrace(empty_error.New("certificate file path")),
		)
	}

	keyFilePath := config.KeyFilePath
	if keyFilePath == "" {
		logFatal(
			"Empty key file path.",
			motmedelErrors.NewWithTrace(empty_error.New("key file path")),
		)
	}

	configFilePath := config.ConfigFilePath
	if configFilePath == "" {
		logFatal(
			"Empty config path.",
			motmedelErrors.NewWithTrace(empty_error.New("config file path")),
		)
	}

	// Read the configuration file.

	configData, err := os.ReadFile(configFilePath)
	if err != nil {
		logFatal(
			"An error occurred when reading the configuration file.",
			motmedelErrors.NewWithTrace(fmt.Errorf("os read file (config): %w", err)),
			configFilePath,
		)
	}

	var hostToUpstreamConfiguration map[string]*UpstreamConfiguration
	if err := json.Unmarshal(configData, &hostToUpstreamConfiguration); err != nil {
		logFatal(
			"An error occurred when decoding the configuration file.",
			motmedelErrors.NewWithTrace(fmt.Errorf("json unmarshal (config): %w", err)),
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
			motmedelErrors.NewWithTrace(fmt.Errorf("os read file (certificate): %w", err), certificateFilePath),
		)
	}
	if len(certificateData) == 0 {
		logFatal(
			"Empty certificate data.",
			motmedelErrors.NewWithTrace(empty_error.New("certificate data")),
		)
	}

	keyData, err := os.ReadFile(keyFilePath)
	if err != nil {
		logFatal(
			"An error occurred when reading the key file.",
			motmedelErrors.NewWithTrace(fmt.Errorf("os read file (key): %w", err), keyFilePath),
		)
	}
	if len(keyData) == 0 {
		logFatal(
			"Empty key data.",
			motmedelErrors.NewWithTrace(empty_error.New("key data")),
		)
	}

	certificate, err := tls.X509KeyPair(certificateData, keyData)
	if err != nil {
		logFatal(
			"An error occurred when parsing the certificate and key.",
			motmedelErrors.NewWithTrace(fmt.Errorf("tls x509 key pair: %w", err)),
		)
	}

	// Make the Vhost mux configuration.

	hostToSpecification := make(map[string]*motmedelMux.VhostMuxSpecification)

	for host, upstreamConfiguration := range hostToUpstreamConfiguration {
		if upstreamConfiguration == nil {
			logFatal(
				"Empty upstream configuration.",
				motmedelErrors.NewWithTrace(nil_error.New("upstream configuration")),
			)
		}

		upstreamUrl := upstreamConfiguration.Url
		if upstreamUrl == "" {
			logFatal(
				"Empty upstream URL.",
				motmedelErrors.NewWithTrace(empty_error.New("upstream url")),
			)
		}

		target, err := url.Parse(upstreamUrl)
		if err != nil {
			logFatal(
				"An error occurred when parsing an upstream URL.",
				motmedelErrors.NewWithTrace(fmt.Errorf("url parse: %w", err)),
				upstreamUrl,
			)
		}

		var specification *motmedelMux.VhostMuxSpecification

		if upstreamConfiguration.Redirect {
			specification = &motmedelMux.VhostMuxSpecification{RedirectTo: upstreamUrl}
		} else {
			proxy := httputil.NewSingleHostReverseProxy(target)

			originalDirector := proxy.Director
			proxy.Director = func(request *http.Request) {
				if request == nil {
					logError(
						"Empty HTTP request.",
						motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequest),
					)
					return
				}

				originalDirector(request)

				if request.Header == nil {
					logError(
						"Empty HTTP request header.",
						motmedelErrors.NewWithTrace(motmedelHttpErrors.ErrNilHttpRequestHeader),
					)
					return
				}

				setForwardedHeaders(request)
			}

			proxyLogger := makeLogger(
				slog.String("dataset", "reverse_proxy"),
				slog.String("reason", "A proxy error occurred."),
			)
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				proxyLogger.Error(
					err.Error(),
					motmedelErrors.NewWithTrace(fmt.Errorf("proxy: %w", err)),
				)
				w.WriteHeader(http.StatusBadGateway)
			}

			specification = &motmedelMux.VhostMuxSpecification{Mux: proxy}
		}

		hostToSpecification[host] = specification
	}

	vhostMux := &motmedelMux.VhostMux{HostToSpecification: hostToSpecification}
	if config.Verbose {
		vhostMux.DoneCallback = func(ctx context.Context) {
			slog.DebugContext(ctx, "An HTTP response was served.")
		}
	}

	server := &http.Server{
		Addr:    serverAddress,
		Handler: vhostMux,
		TLSConfig: &tls.Config{
			GetConfigForClient: func(clientHelloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
				if clientHelloInfo == nil {
					return nil, motmedelErrors.NewWithTrace(nil_error.New("client hello info"))
				}

				cfg, ok := hostToUpstreamConfiguration[clientHelloInfo.ServerName]
				if !ok {
					// Fail the TLS handshake when there is no matching configuration for the server name.
					return nil, fmt.Errorf("no upstream configuration for SNI %q", clientHelloInfo.ServerName)
				}

				if cfg == nil {
					return nil, motmedelErrors.NewWithTrace(nil_error.New("upstream configuration"))
				}

				tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}}

				if cfg.UseClientAuthentication {
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
					// TODO: I cannot make "CA pinning" work... Something for future?
				}

				return tlsConfig, nil
			},
		},
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		logFatal(
			"An error occurred when listening and serving.",
			motmedelErrors.NewWithTrace(fmt.Errorf("http listen and serve: %w", err)),
		)
	}
}
