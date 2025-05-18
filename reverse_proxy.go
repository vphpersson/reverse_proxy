package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelEnv "github.com/Motmedel/utils_go/pkg/env"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
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
	Url                     string
	UseClientAuthentication bool
}

var hostToUpstreamConfiguration map[string]*UpstreamConfiguration

var (
	ErrNilClientHelloInfo       = errors.New("nil client hello info")
	ErrNilUpstreamConfiguration = errors.New("nil upstream configuration")
	ErrEmptyUpstreamUrl         = errors.New("empty upstream url")
	ErrEmptyCertificateFilePath = errors.New("empty certificate file path")
	ErrEmptyKeyFilePath         = errors.New("empty key file path")
	ErrEmptyCertificateData     = errors.New("empty certificate data")
	ErrEmptyServerAddress       = errors.New("empty server address")
	ErrEmptyKeyData             = errors.New("empty key data")
)

func main() {
	logger := &motmedelErrorLogger.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Next: slog.NewJSONHandler(
					os.Stdout,
					&slog.HandlerOptions{
						AddSource:   false,
						Level:       slog.LevelInfo,
						ReplaceAttr: ecs.TimestampReplaceAttr,
					},
				),
				Extractors: []motmedelLog.ContextExtractor{
					&motmedelLog.ErrorContextExtractor{},
				},
			},
		).With(slog.Group("event", slog.String("dataset", "reverse_proxy"))),
	}
	slog.SetDefault(logger.Logger)

	var serverAddress string
	flag.StringVar(
		&serverAddress,
		"addr",
		motmedelEnv.GetEnvWithDefault("SERVER_ADDRESS", ":443"),
		"HTTP server address",
	)

	var certificateFilePath string
	flag.StringVar(
		&certificateFilePath,
		"cert",
		motmedelEnv.GetEnvWithDefault("CERTIFICATE_FILE_PATH", ""),
		"Path to TLS certificate file",
	)

	var keyFilePath string
	flag.StringVar(
		&keyFilePath,
		"key",
		motmedelEnv.GetEnvWithDefault("CERTIFICATE_KEY_PATH", ""),
		"Path to TLS key file",
	)

	flag.Parse()

	if serverAddress == "" {
		logger.FatalWithExitingMessage(
			"Empty server address.",
			motmedelErrors.NewWithTrace(ErrEmptyServerAddress),
		)
	}

	if certificateFilePath == "" {
		logger.FatalWithExitingMessage(
			"Empty certificate file path.",
			motmedelErrors.NewWithTrace(ErrEmptyCertificateFilePath),
		)
	}

	if keyFilePath == "" {
		logger.FatalWithExitingMessage(
			"Empty key file path.",
			motmedelErrors.NewWithTrace(ErrEmptyKeyFilePath),
		)
	}

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

	certificatePool := x509.NewCertPool()
	certificateDerBlockBytes := certificate.Certificate[0]
	x509Certificate, err := x509.ParseCertificate(certificateDerBlockBytes)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when parsing a certificate DER block bytes as a x509 certificate.",
			motmedelErrors.NewWithTrace(fmt.Errorf("x509 parse certificate: %w", err)),
		)
	}
	certificatePool.AddCert(x509Certificate)

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

	srv := &http.Server{
		Addr:         serverAddress,
		Handler:      vhostMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig: &tls.Config{
			GetConfigForClient: func(clientHelloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
				if clientHelloInfo == nil {
					return nil, ErrNilClientHelloInfo
				}

				cfg, ok := hostToUpstreamConfiguration[clientHelloInfo.ServerName]
				if !ok {
					// Fail the TLS handshake.
					return nil, nil
				}

				if cfg == nil {
					return nil, motmedelErrors.NewWithTrace(ErrNilUpstreamConfiguration)
				}

				tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}}

				if cfg.UseClientAuthentication {
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
					tlsConfig.ClientCAs = certificatePool
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
