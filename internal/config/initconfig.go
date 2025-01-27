package config

import (
	"os"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// GetConfigOpt -- Get db, redis, mailer, grpc, jwt, oauth, user, tracer
func GetConfigOpt(log *zap.Logger, v *viper.Viper) (*RedisOptions, *MailerOptions, *ServerOptions, *GrpcServerOptions, *OauthOptions, *UserOptions, *UptraceOptions) {
	redisOpt, err := GetRedisConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9102), zap.Error(err))
		os.Exit(1)
	}

	mailerOpt, err := GetMailerConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9103), zap.Error(err))
		os.Exit(1)
	}

	serverOpt, err := GetServerConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9104), zap.Error(err))
		os.Exit(1)
	}

	grpcServerOpt, err := GetGrpcServerConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9104), zap.Error(err))
		os.Exit(1)
	}

	oauthOpt, err := GetOauthConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9106), zap.Error(err))
		os.Exit(1)
	}

	userOpt, err := GetUserConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9107), zap.Error(err))
		os.Exit(1)
	}

	/*jaegerTracerOpt, err := GetJaegerTracerConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9108), zap.Error(err))
		os.Exit(1)
	}

	promOpt, err := GetPromConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9109), zap.Error(err))
		os.Exit(1)
	}*/
	uptraceOpt, err := GetUptraceConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9109), zap.Error(err))
		os.Exit(1)
	}
	return redisOpt, mailerOpt, serverOpt, grpcServerOpt, oauthOpt, userOpt, uptraceOpt
}
