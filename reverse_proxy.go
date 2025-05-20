package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelEnv "github.com/Motmedel/utils_go/pkg/env"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelHttpLog "github.com/Motmedel/utils_go/pkg/http/log"
	motmedelMux "github.com/Motmedel/utils_go/pkg/http/mux"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

type UpstreamConfiguration struct {
	Url                     string `json:"url,omitempty"`
	UseClientAuthentication bool   `json:"use_client_authentication,omitempty"`
}

var (
	ErrNilClientHelloInfo       = errors.New("nil client hello info")
	ErrNilUpstreamConfiguration = errors.New("nil upstream configuration")
	ErrEmptyUpstreamUrl         = errors.New("empty upstream url")
	ErrEmptyCertificateFilePath = errors.New("empty certificate file path")
	ErrEmptyKeyFilePath         = errors.New("empty key file path")
	ErrEmptyCertificateData     = errors.New("empty certificate data")
	ErrEmptyServerAddress       = errors.New("empty server address")
	ErrEmptyKeyData             = errors.New("empty key data")
	ErrEmptyConfigFilePath      = errors.New("empty config file path")
	ErrNilConfig                = errors.New("nil config")
)

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
	var logLevel slog.LevelVar

	logger := &motmedelErrorLogger.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Next: slog.NewJSONHandler(
					os.Stdout,
					&slog.HandlerOptions{
						AddSource:   false,
						Level:       &logLevel,
						ReplaceAttr: ecs.TimestampReplaceAttr,
					},
				),
				Extractors: []motmedelLog.ContextExtractor{
					&motmedelLog.ErrorContextExtractor{},
					&motmedelHttpLog.HttpContextExtractor{},
				},
			},
		).With(slog.Group("event", slog.String("dataset", "reverse_proxy"))),
	}
	slog.SetDefault(logger.Logger)

	config := parseFlags()
	if config == nil {
		logger.FatalWithExitingMessage("Empty configuration.", motmedelErrors.NewWithTrace(ErrNilConfig))
	}

	verbose := config.Verbose
	if verbose {
		logLevel.Set(slog.LevelDebug)
	}

	serverAddress := config.ServerAddress
	if serverAddress == "" {
		logger.FatalWithExitingMessage(
			"Empty server address.",
			motmedelErrors.NewWithTrace(ErrEmptyServerAddress),
		)
	}

	certificateFilePath := config.CertificateFilePath
	if certificateFilePath == "" {
		logger.FatalWithExitingMessage(
			"Empty certificate file path.",
			motmedelErrors.NewWithTrace(ErrEmptyCertificateFilePath),
		)
	}

	keyFilePath := config.KeyFilePath
	if keyFilePath == "" {
		logger.FatalWithExitingMessage(
			"Empty key file path.",
			motmedelErrors.NewWithTrace(ErrEmptyKeyFilePath),
		)
	}

	configFilePath := config.ConfigFilePath
	if configFilePath == "" {
		logger.FatalWithExitingMessage(
			"Empty config path.",
			motmedelErrors.NewWithTrace(ErrEmptyConfigFilePath),
		)
	}

	// Read the configuration file.

	configData, err := os.ReadFile(configFilePath)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when reading the configuration file.",
			motmedelErrors.NewWithTrace(fmt.Errorf("os read file (config): %w", err)),
			configFilePath,
		)
	}

	var hostToUpstreamConfiguration map[string]*UpstreamConfiguration
	if err := json.Unmarshal(configData, &hostToUpstreamConfiguration); err != nil {
		logger.FatalWithExitingMessage(
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
		logger.FatalWithExitingMessage(
			"An error occurred when reading the certificate file.",
			motmedelErrors.NewWithTrace(fmt.Errorf("os read file (certificate): %w", err), certificateFilePath),
		)
	}
	if len(certificateData) == 0 {
		logger.FatalWithExitingMessage(
			"Empty certificate data.",
			motmedelErrors.NewWithTrace(ErrEmptyCertificateData),
		)
	}

	keyData, err := os.ReadFile(keyFilePath)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when reading the certificate file.",
			motmedelErrors.NewWithTrace(fmt.Errorf("os read file (key): %w", err), certificateFilePath),
		)
	}
	if len(keyData) == 0 {
		logger.FatalWithExitingMessage(
			"Empty key data.",
			motmedelErrors.NewWithTrace(ErrEmptyKeyData),
		)
	}

	certificate, err := tls.X509KeyPair(certificateData, keyData)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when parsing the certificate and key.",
			motmedelErrors.NewWithTrace(fmt.Errorf("tls x509 key pair: %w", err)),
		)
	}

	// Make the Vhost mux configuration.

	hostToSpecification := make(map[string]*motmedelMux.VhostMuxSpecification)

	for host, upstreamConfiguration := range hostToUpstreamConfiguration {
		if upstreamConfiguration == nil {
			logger.FatalWithExitingMessage(
				"Empty upstream configuration.",
				motmedelErrors.NewWithTrace(ErrNilUpstreamConfiguration),
			)
		}

		upstreamUrl := upstreamConfiguration.Url
		if upstreamUrl == "" {
			logger.FatalWithExitingMessage(
				"Empty upstream URL.",
				motmedelErrors.NewWithTrace(ErrEmptyUpstreamUrl),
			)
		}

		target, err := url.Parse(upstreamUrl)
		if err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when parsing an upstream URL.",
				motmedelErrors.NewWithTrace(fmt.Errorf("url parse: %w", err)),
				upstreamUrl,
			)
		}

		hostToSpecification[host] = &motmedelMux.VhostMuxSpecification{
			Mux: httputil.NewSingleHostReverseProxy(target),
		}
	}

	vhostMux := &motmedelMux.VhostMux{HostToSpecification: hostToSpecification}
	if verbose {
		vhostMux.DoneCallback = func(ctx context.Context) {
			slog.DebugContext(ctx, "An HTTP response was served.")
		}
	}

	srv := &http.Server{
		Addr:         serverAddress,
		Handler:      vhostMux,
		ReadTimeout:  3 * time.Minute,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig: &tls.Config{
			GetConfigForClient: func(clientHelloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
				if clientHelloInfo == nil {
					return nil, ErrNilClientHelloInfo
				}

				cfg, ok := hostToUpstreamConfiguration[clientHelloInfo.ServerName]
				if !ok {
					// Fail the TLS handshake when there is no matching configuration for the server name.
					return nil, nil
				}

				if cfg == nil {
					return nil, motmedelErrors.NewWithTrace(ErrNilUpstreamConfiguration)
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

	if err := srv.ListenAndServeTLS("", ""); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when listening and serving.",
			motmedelErrors.NewWithTrace(fmt.Errorf("http listen and serve: %w", err)),
		)
	}
}
