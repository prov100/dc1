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

type UserEmail struct {
	Email string
}

func setEmail(ctx context.Context, u *UserEmail) context.Context {
	return context.WithValue(ctx, "email", u)
}

func getEmail(ctx context.Context) *UserEmail {
	user, ok := ctx.Value("email").(*UserEmail)

	if !ok {
		return nil
	}

	return user
}

/*** APIG start ***/
// API Gateway configuration
const (
	BackendServiceURL = "http://localhost:9061" // Backend service URL
)

// ReverseProxy creates a reverse proxy to the backend service
func ReverseProxy(target string) http.Handler {
	fmt.Println("ReverseProxy started")
	fmt.Println("ReverseProxy target", target)
	targetURL, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	return proxy
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
	fmt.Println("main started")
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

	jwtOpt, err := config.GetJWTConfig(log, v, false, "SC_DCSA_JWT_KEY", "SC_DCSA_JWT_DURATION")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 103), zap.Error(err))
		os.Exit(1)
	}

	common.SetJWTOpt(jwtOpt)

	// Create a ServeMux for routing
	mux := http.NewServeMux()

	// Chain middleware: logging -> JWT validation
	chain := common.ChainMiddlewares(
		// middleware.LoggingMiddleware(logger),
		common.HandleCacheControl,
		common.CorsMiddleware,
		common.ValidateToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain),
	)

	// Create a proxy handler for the backend service
	proxyHandler := NewProxyHandler(BackendServiceURL)

	// Apply the middleware chain to all routes
	mux.Handle("/v0.1/users", chain(proxyHandler))

	/*** APIG start ***/

	// Create a reverse proxy to the backend service
	// backendProxy := ReverseProxy(BackendServiceURL)

	// fmt.Println("main backendProxy", backendProxy)

	/*proxy := ReverseProxy(BackendServiceURL)

	// Set up the API Gateway routes
	mux := http.NewServeMux()

	// Catch-all route to forward all requests to the backend service
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("main mux.HandleFunc function r", r)
		fmt.Println("main mux.HandleFunc function r.Context()", r.Context())
		// proxy := ReverseProxy(BackendServiceURL)
		fmt.Println("main mux.HandleFunc function ReverseProxy r", r)
		fmt.Println("main mux.HandleFunc function ReverseProxy r.Context()", r.Context())
		// ctx := r.Context()

		// find key value which is set in validate token method
		// a := r.Context().Value(common.KeyEmailToken)
		// emailToken, _ := a.(common.ContextStruct)
		// fmt.Println("emailToken", emailToken)

		// req := r.WithContext(context.WithValue(ctx, common.KeyEmailToken, emailToken))

		ctx := setEmail(r.Context(), &UserEmail{
			Email: "sprov300@gmail.com",
		})

		req := r.WithContext(ctx)

		fmt.Println("req is", req)
		fmt.Println("req.Context()", req.Context())

		email := getEmail(req.Context())
		fmt.Println("email is", email)

		reqDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Printf("REQUEST:\n%s", string(reqDump))

		fmt.Println("started")
		proxy.ServeHTTP(w, req)
		fmt.Println("ended")
	})*/

	/*mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("main mux.HandleFunc function r", r)
		fmt.Println("main mux.HandleFunc function r.Context()", r.Context())
		// proxy := ReverseProxy(BackendServiceURL)
		fmt.Println("main mux.HandleFunc function ReverseProxy r", r)
		fmt.Println("main mux.HandleFunc function ReverseProxy r.Context()", r.Context())
		ctx := r.Context()

		// find key value which is set in validate token method
		a := r.Context().Value(common.KeyEmailToken)
		emailToken, _ := a.(common.ContextStruct)
		fmt.Println("emailToken", emailToken)

		req := r.WithContext(context.WithValue(ctx, common.KeyEmailToken, emailToken))
		//*r = *req
		fmt.Println("req is", req)
		fmt.Println("req.Context()", req.Context())

		reqDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Printf("REQUEST:\n%s", string(reqDump))

		fmt.Println("started")
		proxy.ServeHTTP(w, req)
		fmt.Println("ended")
	})*/

	// Middleware to inject context values into the request
	/*injectContext := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// find key value which is set in validate token method
			a := r.Context().Value(common.KeyEmailToken)
			emailToken, _ := a.(common.ContextStruct)
			fmt.Println("emailToken", emailToken)

			// Add a context value to the request
			ctx := context.WithValue(r.Context(), common.KeyEmailToken, "12345") // Example userID
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	mux.Handle("/", injectContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})))*/

	fmt.Println("main mux2222222222")

	/*** APIG end ***/

	// Chain middlewares
	/*finalHandler := common.ChainMiddlewares(
		common.HandleCacheControl,
		common.CorsMiddleware,
		common.ValidateToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain),
	)(mux)*/

	fmt.Println("main mux333333333333333")
	if serverOpt.ServerTLS == "true" {
		fmt.Println("main mux4444444444444 ServerTLS true")
		var caCertPath, certPath, keyPath string
		var tlsConfig *tls.Config
		pwd, _ := os.Getwd()
		caCertPath = pwd + filepath.FromSlash(serverOpt.CaCertPath)
		certPath = pwd + filepath.FromSlash(serverOpt.CertPath)
		keyPath = pwd + filepath.FromSlash(serverOpt.KeyPath)

		tlsConfig = getKeys(log, caCertPath, certPath, keyPath)

		fmt.Println("main:serverOpt.ApigServerAddr", serverOpt.ApigServerAddr)
		srv := &http.Server{
			Addr:      ":" + serverOpt.ApigServerAddr,
			Handler:   mux, // finalHandler, // mux,
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

		fmt.Println("main:Starting server in TLS true")
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
		fmt.Println("main mux4444444444444 ServerTLS false")
		srv := &http.Server{
			Addr:    ":" + serverOpt.ApigServerAddr,
			Handler: mux, // finalHandler, // mux,
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

		fmt.Println("server started at port", serverOpt.ApigServerAddr)
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

func NewProxyHandler(backendURL string) http.Handler {
	backend, _ := url.Parse(backendURL)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// Copy the original request's context to the new request
			fmt.Println("NewProxyHandler r.In.Context()", r.In.Context())

			r.Out = r.Out.WithContext(r.In.Context())
			fmt.Println("NewProxyHandler r.Out", r.Out)
			fmt.Println("NewProxyHandler r.Out.Context()", r.Out.Context())
			// print keyemailtoken which we sent to request
			fmt.Println("NewProxyHandler context value", r.Out.Context().Value(common.KeyEmailToken).(common.ContextStruct))

			// Set the backend URL and other headers
			r.SetURL(backend)
			r.SetXForwarded()
			r.Out.Header.Set("X-Forwarded-Host", r.In.Header.Get("Host"))
			r.Out.Host = backend.Host
		},
	}
	return proxy
}
