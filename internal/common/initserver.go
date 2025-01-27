package common

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/prov100/dc1/internal/config"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
)

// GetServices - Init Db, Redis, and Mailer services
func GetServices(log *zap.Logger, isTest bool, dbOpt *config.DBOptions, redisOpt *config.RedisOptions, jwtOpt *config.JWTOptions, mailerOpt *config.MailerOptions) (*DBService, *RedisService, *MailerService) {
	dbService, err := CreateDBService(log, dbOpt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9120), zap.Error(err))
		os.Exit(1)
	}

	redisService, err := CreateRedisService(log, redisOpt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9121), zap.Error(err))
		os.Exit(1)
	}
	mailerService := &MailerService{}
	if !isTest {
		mailerService, err = CreateMailerService(log, mailerOpt)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 9122), zap.Error(err))
			os.Exit(1)
		}
	}
	return dbService, redisService, mailerService
}

// GetSrvCred -- server credentials
func GetSrvCred(log *zap.Logger, isTest bool, pwd string, grpcServerOpt *config.GrpcServerOptions) (credentials.TransportCredentials, error) {
	var certPath, keyPath string
	fmt.Println("grpcServerOpt.GrpcCertPath is", grpcServerOpt.GrpcCertPath)
	fmt.Println("grpcServerOpt.GrpcKeyPath is", grpcServerOpt.GrpcKeyPath)
	fmt.Println("filepath.FromSlash(grpcServerOpt.GrpcCertPath) is", filepath.FromSlash(grpcServerOpt.GrpcCertPath))
	fmt.Println("filepath.FromSlash(grpcServerOpt.GrpcKeyPath) is", filepath.FromSlash(grpcServerOpt.GrpcKeyPath))
	if isTest {
		certPath = filepath.Join(pwd, filepath.FromSlash("/../../../")+filepath.FromSlash(grpcServerOpt.GrpcCertPath))
		keyPath = filepath.Join(pwd, filepath.FromSlash("/../../../")+filepath.FromSlash(grpcServerOpt.GrpcKeyPath))
	} else {
		// certPath = filepath.Join(pwd, filepath.FromSlash("/../../../")+filepath.FromSlash(grpcServerOpt.GrpcCertPath))
		// keyPath = filepath.Join(pwd, filepath.FromSlash("/../../../")+filepath.FromSlash(grpcServerOpt.GrpcKeyPath))
		certPath = pwd + filepath.FromSlash(grpcServerOpt.GrpcCertPath)
		keyPath = pwd + filepath.FromSlash(grpcServerOpt.GrpcKeyPath)
		// certPath = filepath.FromSlash(grpcServerOpt.GrpcCertPath)
		// keyPath =  filepath.FromSlash(grpcServerOpt.GrpcKeyPath)
		// certPath = grpcServerOpt.GrpcCertPath
		// keyPath = grpcServerOpt.GrpcKeyPath
	}
	fmt.Println("certPath", certPath)
	fmt.Println("keyPath", keyPath)
	creds, err := credentials.NewServerTLSFromFile(certPath, keyPath)
	fmt.Println("creds", creds)
	fmt.Println("err", err)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9128), zap.Error(err))
		return nil, err
	}

	return creds, nil
}

// GetClientCred -- client credentials
func GetClientCred(log *zap.Logger, isTest bool, pwd string, grpcServerOpt *config.GrpcServerOptions) (credentials.TransportCredentials, error) {
	var caCertKeyPath string
	if isTest {
		caCertKeyPath = filepath.Join(pwd, filepath.FromSlash("/../../../")+filepath.FromSlash(grpcServerOpt.GrpcCaCertPath))
	} else {
		// caCertKeyPath = grpcServerOpt.GrpcCaCertPath
		caCertKeyPath = pwd + filepath.FromSlash(grpcServerOpt.GrpcCaCertPath)
	}

	creds, err := credentials.NewClientTLSFromFile(caCertKeyPath, "localhost")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9130), zap.Error(err))
		return nil, err
	}

	return creds, nil
}
