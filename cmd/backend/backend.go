package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"

	_ "github.com/go-sql-driver/mysql" // mysql
	"github.com/prov100/dc1/internal/common"
	"github.com/prov100/dc1/internal/config"
	"github.com/prov100/dc1/internal/controllers/partycontrollers"
	"github.com/throttled/throttled/v2/store/goredisstore"
	"go.uber.org/zap"
)

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

	redisOpt, _, _, grpcServerOpt, _, _, uptraceOpt := config.GetConfigOpt(log, v)

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
	}

	mux := http.NewServeMux()
	configFilePath := v.GetString("SC_DCSA_WORKFLOW_CONFIG_FILE_PATH")
	err = partycontrollers.Init(log, mux, store, serverOpt, grpcServerOpt, uptraceOpt, configFilePath)
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 110),
			zap.Error(err))
		os.Exit(1)
	}

	if serverOpt.ServerTLS == "true" {
		var caCertPath, certPath, keyPath string
		var tlsConfig *tls.Config
		pwd, _ := os.Getwd()
		caCertPath = pwd + filepath.FromSlash(serverOpt.CaCertPath)
		certPath = pwd + filepath.FromSlash(serverOpt.CertPath)
		keyPath = pwd + filepath.FromSlash(serverOpt.KeyPath)

		tlsConfig = getKeys(log, caCertPath, certPath, keyPath)

		fmt.Println("main:serverOpt.BackendServerAddr", serverOpt.BackendServerAddr)
		srv := &http.Server{
			Addr:      ":" + serverOpt.BackendServerAddr,
			Handler:   mux, // mux,
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
			Addr:    ":" + serverOpt.BackendServerAddr,
			Handler: mux, // mux,
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

		fmt.Println("server started at port", serverOpt.BackendServerAddr)
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
