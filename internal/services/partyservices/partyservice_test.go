package partyservices

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/prov100/dc1/internal/common"
	"github.com/prov100/dc1/internal/config"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"

	// interceptors "github.com/prov100/dc1/internal/interceptors"
	_ "github.com/go-sql-driver/mysql"
	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"
	"github.com/prov100/dc1/test"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	//"github.com/auth0/go-auth0/authentication"
	//"github.com/auth0/go-auth0/authentication/oauth"
)

var (
	dbService         *common.DBService
	redisService      *common.RedisService
	userServiceClient partyproto.UserServiceClient
	mailerService     common.MailerIntf
	jwtOpt            *config.JWTOptions
	// userOpt           *config.UserOptions
	userTestOpt *config.UserTestOptions
	// serverOpt         *config.ServerOptions

	redisOpt      *config.RedisOptions
	mailerOpt     *config.MailerOptions
	serverOpt     *config.ServerOptions
	grpcServerOpt *config.GrpcServerOptions
	oauthOpt      *config.OauthOptions
	userOpt       *config.UserOptions
	uptraceOpt    *config.UptraceOptions
)

var (
	// log          *zap.Logger
	logParty *zap.Logger
	logUser  *zap.Logger
	Layout   string
)

func TestMain(m *testing.M) {
	var err error

	v, err := config.GetViper()
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8307), zap.Error(err))
		os.Exit(1)
	}

	logOpt, err := config.GetLogConfig(v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8307), zap.Error(err))
		os.Exit(1)
	}

	log = config.SetUpLogging(logOpt.Path)
	logUser = config.SetUpLogging(logOpt.UserPath)
	logParty = config.SetUpLogging(logOpt.PartyPath)
	Layout = "2006-01-02T15:04:05Z"

	dbOpt, err := config.GetDbConfig(log, v, true, "SC_DCSA_DB", "SC_DCSA_DBHOST", "SC_DCSA_DBPORT", "SC_DCSA_DBUSER_TEST", "SC_DCSA_DBPASS_TEST", "SC_DCSA_DBNAME_TEST", "SC_DCSA_DBSQL_MYSQL_TEST", "SC_DCSA_DBSQL_MYSQL_SCHEMA", "SC_DCSA_DBSQL_MYSQL_TRUNCATE", "SC_DCSA_DBSQL_PGSQL_TEST", "SC_DCSA_DBSQL_PGSQL_SCHEMA", "SC_DCSA_DBSQL_PGSQL_TRUNCATE")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
		return
	}

	jwtOpt, err = config.GetJWTConfig(log, v, true, "SC_DCSA_JWT_KEY_TEST", "SC_DCSA_JWT_DURATION_TEST")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
		return
	}

	userTestOpt, err = config.GetUserTestConfig(log, v)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
		return
	}

	redisOpt, mailerOpt, serverOpt, grpcServerOpt, oauthOpt, userOpt, uptraceOpt = config.GetConfigOpt(log, v)
	fmt.Println("TestMain serverOpt", serverOpt)

	dbService, redisService, _ = common.GetServices(log, true, dbOpt, redisOpt, jwtOpt, mailerOpt)

	mailerService, err := test.CreateMailerServiceTest(log)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8016), zap.Error(err))
	}

	pwd, _ := os.Getwd()
	go StartUserServer(logUser, true, pwd, dbOpt, redisOpt, mailerOpt, serverOpt, grpcServerOpt, jwtOpt, oauthOpt, userOpt, uptraceOpt, dbService, redisService, mailerService)
	go StartPartyServer(logParty, true, pwd, dbOpt, redisOpt, mailerOpt, grpcServerOpt, jwtOpt, oauthOpt, userOpt, uptraceOpt, dbService, redisService, mailerService)
	// go userworkers.StartUserWorker(log, true, pwd, grpcServerOpt, uptraceOpt, configFilePath)

	keyPath := filepath.Join(pwd, filepath.FromSlash("/../../../")+filepath.FromSlash(grpcServerOpt.GrpcCaCertPath))
	creds, err := credentials.NewClientTLSFromFile(keyPath, "localhost")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
	}

	/*tracer4, _ := interceptors.NewJaegerTracer(log, jaegerTracerOpt, jaegerTracerOpt.UserServiceName)
	userconn, err := grpc.NewClient(grpcServerOpt.GrpcUserServerPort, grpc.WithUserAgent(jaegerTracerOpt.UserAgent), grpc.WithTransportCredentials(creds), grpc.WithUnaryInterceptor(grpc_opentracing.UnaryClientInterceptor(grpc_opentracing.WithTracer(tracer4))))*/
	userconn, err := grpc.NewClient(grpcServerOpt.GrpcUserServerPort, grpc.WithTransportCredentials(creds), grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8301), zap.Error(err))
		return
	}

	userServiceClient = partyproto.NewUserServiceClient(userconn)
	fmt.Println("TestMain serverOpt", serverOpt)
	os.Exit(m.Run())
}

/*func LoginUser() context.Context {
	form := partyproto.LoginRequest{}
	form.Email = userTestOpt.Email
	form.Password = userTestOpt.Password
	form.RequestId = userTestOpt.RequestId
	userService := NewUserService(log, dbService, redisService, tokenService, mailerService, jwtOpt, userOpt, authEnforcer)
	ctx := context.Background()
	userResponse, err := userService.Login(ctx, &form)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8307), zap.Error(err))
		return nil
	}
	tokenString := userResponse.AccessToken
	md := metadata.Pairs("authorization", "Bearer "+tokenString)
	ctxNew := metadata.NewIncomingContext(context.Background(), md)
	return ctxNew
}*/

func LoginUser() context.Context {
	fmt.Println("in Login User userTestOpt.Tokenstring", userTestOpt.Tokenstring)
	md := metadata.Pairs("authorization", "Bearer "+userTestOpt.Tokenstring)
	fmt.Println("services/partyservices/partyservice_test.go LoginUser()", md)
	ctxNew := metadata.NewIncomingContext(context.Background(), md)
	fmt.Println("services/partyservices/partyservice_test.go LoginUser() ctxNew", ctxNew)
	return ctxNew
}

/*func LoginUser() context.Context {
	domain := "dev-llzybv0gk4ybnuqm.us.auth0.com"
	clientID := "xStBKcCvjs9cCXgyvAxn0202D5MwtyDV"
	clientSecret := "NEzc11dTF_Kka5EQZN6Kp9HvQOTZGyOjeX9XCdstpvR4xtafR4oeaqifAvnAPn8-"
	audience := "https://hello-world.example.com"

	// Initialize a new client using a domain, client ID and client secret.
	authAPI, err := authentication.New(
		context.TODO(), // Replace with a Context that better suits your usage
		domain,
		authentication.WithClientID(clientID),
		authentication.WithClientSecret(clientSecret), // Optional depending on the grants used
	)
	if err != nil {
		fmt.Println("failed to initialize the auth0 authentication API client", err)
	}
	accessToken, err := LoginWithClientCredentials(authAPI, clientSecret, audience)
	fmt.Println("LoginUser() accessToken", accessToken)
	fmt.Println("LoginUser() err is", err)
	if err != nil {
		fmt.Println("err", err)
		return nil
	}

	md := metadata.Pairs("authorization", "Bearer "+accessToken)
	ctxNew := metadata.NewIncomingContext(context.Background(), md)

	return ctxNew
}

func LoginWithClientCredentials(authAPI *authentication.Authentication, clientSecret string, audience string) (string, error) {
	tokenSet, err := authAPI.OAuth.LoginWithClientCredentials(context.Background(), oauth.LoginWithClientCredentialsRequest{
		ClientAuthentication: oauth.ClientAuthentication{
			ClientSecret: clientSecret,
		},
		Audience: audience,
	}, oauth.IDTokenValidationOptions{})
	if err != nil {
		fmt.Println("LoginWithClientCredentials err", err)
		return "", err
	}
	fmt.Println("tokenSet", tokenSet)
	fmt.Println("tokenSet.Scope", tokenSet.Scope)
	fmt.Println("tokenSet.AccessToken", tokenSet.AccessToken)
	fmt.Println("tokenSet.TokenType", tokenSet.TokenType)

	return tokenSet.AccessToken, nil
}*/
