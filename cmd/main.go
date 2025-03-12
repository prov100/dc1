package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"

	_ "github.com/go-sql-driver/mysql" // mysql
	"github.com/prov100/dc1/internal/common"
	"github.com/prov100/dc1/internal/config"
	"go.uber.org/zap"
)

/*** APIG start ***/
// API Gateway configuration
const (
	BackendServiceURL = "http://localhost:9061" // Backend service URL
)

// ReverseProxy creates a reverse proxy to the backend service
func ReverseProxy(target string) http.Handler {
	targetURL, _ := url.Parse(target)
	return httputil.NewSingleHostReverseProxy(targetURL)
}

/*** APIG end ***/

func getKeys(log *zap.Logger, caCertPath string, certPath string, keyPath string) *tls.Config {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 101),
			zap.Error(err))
	}

	caCertpool := x509.NewCertPool()
	caCertpool.AppendCertsFromPEM(caCert)

	// LoadX509KeyPair reads files, so we give it the paths
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 102),
			zap.Error(err))
	}

	tlsConfig := tls.Config{
		ClientCAs:    caCertpool,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return &tlsConfig
}

func main() {
	v, err := config.GetViper()
	if err != nil {
		os.Exit(1)
	}

	logOpt, err := config.GetLogConfig(v)
	if err != nil {
		os.Exit(1)
	}

	log := config.SetUpLogging(logOpt.Path)

	serverOpt, err := config.GetServerConfig(log, v)
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 103),
			zap.Error(err))
		os.Exit(1)
	}

	/*auth0Config := common.Auth0Config{
		Port:          serverOpt.ServerAddr, // port,
		SecureOptions: config.SecureOptions(),
		CorsOptions:   config.CorsOptions(serverOpt.ClientOriginUrl),
		Audience:      serverOpt.Auth0Audience, // audience,
		Domain:        serverOpt.Auth0Domain,   // domain,
	}

	fmt.Println("main: serverOpt.Auth0Audience", serverOpt.Auth0Audience)
	fmt.Println("main: serverOpt.Auth0Domain", serverOpt.Auth0Domain)

	router := http.NewServeMux()
	newRouter := common.Router(router)
	corsMiddleware := cors.New(auth0Config.CorsOptions)
	routerWithCORS := corsMiddleware.Handler(newRouter)

	secureMiddleware := secure.New(auth0Config.SecureOptions)
	finalHandler := secureMiddleware.Handler(routerWithCORS)

	rateOpt, err := config.GetRateConfig(log, v)
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 103),
			zap.Error(err))
		os.Exit(1)
	}*/

	jwtOpt, err := config.GetJWTConfig(log, v, false, "SC_DCSA_JWT_KEY", "SC_DCSA_JWT_DURATION")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 103), zap.Error(err))
		os.Exit(1)
	}

	common.SetJWTOpt(jwtOpt)

	/*redisOpt, _, _, grpcServerOpt, _, _, uptraceOpt := config.GetConfigOpt(log, v)

	common.SetJWTOpt(jwtOpt)

	redisService, err := common.CreateRedisService(log, redisOpt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 750), zap.Error(err))
		os.Exit(1)
	}

	store, err := goredisstore.New(redisService.RedisClient, "throttled:")
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 754),
			zap.Error(err))
		os.Exit(1)
	}*/

	/*** APIG start ***/

	// Create a reverse proxy to the backend service
	backendProxy := ReverseProxy(BackendServiceURL)

	// Set up the API Gateway routes
	mux := http.NewServeMux()

	// Forward all /v1/users requests to the backend service
	mux.Handle("/v0.1/users/", backendProxy)

	// Forward all /v1/parties requests to the backend service
	mux.Handle("/v0.1/parties/", backendProxy)

	/*** APIG end ***/

	// Chain middlewares
	handler := common.ChainMiddlewares(
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain),
	)(mux)

	// mux := http.NewServeMux()
	/*configFilePath := v.GetString("SC_DCSA_WORKFLOW_CONFIG_FILE_PATH")
	err = partycontrollers.Init(log, rateOpt, jwtOpt, router, store, serverOpt, grpcServerOpt, uptraceOpt, configFilePath)
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 110),
			zap.Error(err))
		os.Exit(1)
	}*/

	if serverOpt.ServerTLS == "true" {
		var caCertPath, certPath, keyPath string
		var tlsConfig *tls.Config
		pwd, _ := os.Getwd()
		caCertPath = pwd + filepath.FromSlash(serverOpt.CaCertPath)
		certPath = pwd + filepath.FromSlash(serverOpt.CertPath)
		keyPath = pwd + filepath.FromSlash(serverOpt.KeyPath)

		tlsConfig = getKeys(log, caCertPath, certPath, keyPath)

		fmt.Println("main:serverOpt.ServerAddr", serverOpt.ServerAddr)
		srv := &http.Server{
			Addr:      ":" + serverOpt.ServerAddr,
			Handler:   finalHandler, // mux,
			TLSConfig: tlsConfig,
		}

		idleConnsClosed := make(chan struct{})
		go func() {
			sigint := make(chan os.Signal, 1)
			signal.Notify(sigint, os.Interrupt)
			<-sigint

			// We received an interrupt signal, shut down.
			if err := srv.Shutdown(context.Background()); err != nil {
				// Error from closing listeners, or context timeout:
				log.Error("Error",
					zap.Int("msgnum", 104),
					zap.Error(errors.New("HTTP server Shutdown")))
			}
			close(idleConnsClosed)
		}()

		fmt.Println("main:Starting server in TLS mode")
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != http.ErrServerClosed {
			fmt.Println("err", err)
			// Error starting or closing listener:
			log.Error("Error",
				zap.Int("msgnum", 105),
				zap.Error(err))
		}
		fmt.Println("err", err)
		log.Error("Error",
			zap.Int("msgnum", 106),
			zap.Error(err))

		<-idleConnsClosed
	} else {

		srv := &http.Server{
			Addr:    ":" + serverOpt.ServerAddr,
			Handler: finalHandler, // mux,
		}
		fmt.Println("server started", srv)
		idleConnsClosed := make(chan struct{})
		go func() {
			sigint := make(chan os.Signal, 1)
			signal.Notify(sigint, os.Interrupt)
			<-sigint

			// We received an interrupt signal, shut down.
			if err := srv.Shutdown(context.Background()); err != nil {
				// Error from closing listeners, or context timeout:
				log.Error("Error",
					zap.Int("msgnum", 107),
					zap.Error(err))
			}
			close(idleConnsClosed)
		}()

		fmt.Println("server started at port", serverOpt.ServerAddr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// Error starting or closing listener:
			log.Error("Error",
				zap.Int("msgnum", 108),
				zap.Error(errors.New("HTTP server ListenAndServe")))
		}

		log.Error("Error",
			zap.Int("msgnum", 109),
			zap.Error(errors.New("server shutting down")))

		<-idleConnsClosed

	}
}
