package partycontrollers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/prov100/dc1/internal/common"
	"github.com/prov100/dc1/internal/config"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"

	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"
	// interceptors "github.com/prov100/dc1/internal/interceptors"

	"github.com/throttled/throttled/v2/store/goredisstore"
	"go.uber.org/cadence/client"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	h              common.WfHelper
	workflowClient client.Client
)

// Init the party controllers
func Init(log *zap.Logger, rateOpt *config.RateOptions, jwtOpt *config.JWTOptions, mux *http.ServeMux, store *goredisstore.GoRedisStore, serverOpt *config.ServerOptions, grpcServerOpt *config.GrpcServerOptions, uptraceOpt *config.UptraceOptions, configFilePath string) error {
	h.SetupServiceConfig(configFilePath)
	var err error
	workflowClient, err = h.Builder.BuildCadenceClient()
	if err != nil {
		panic(err)
	}

	pwd, _ := os.Getwd()
	keyPath := pwd + filepath.FromSlash(grpcServerOpt.GrpcCaCertPath)
	creds, err := credentials.NewClientTLSFromFile(keyPath, "localhost")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
	}

	tp, err := config.InitTracerProvider()
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9108), zap.Error(err))
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Error("Error", zap.Int("msgnum", 9108), zap.Error(err))
		}
	}()

	userconn, err := grpc.NewClient(grpcServerOpt.GrpcUserServerPort, grpc.WithTransportCredentials(creds), grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 113), zap.Error(err))
		return err
	}

	partyconn, err := grpc.NewClient(grpcServerOpt.GrpcPartyServerPort, grpc.WithTransportCredentials(creds), grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
		return err
	}

	u := partyproto.NewUserServiceClient(userconn)
	p := partyproto.NewPartyServiceClient(partyconn)
	// uc := NewUController(log, u, h, workflowClient)
	// usc := NewUserController(log, u, h, workflowClient)
	pp := NewPartyController(log, p, u)

	hrlParty := common.GetHTTPRateLimiter(store, rateOpt.PartyMaxRate, rateOpt.PartyMaxBurst)

	// This route is only accessible if the user has a valid access_token.

	mux.HandleFunc("/api/messages/public",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("in /api/messages/protected r", r)
			fmt.Println("in /api/messages/protected")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Hello from a Public"}`))
		}),
	)

	// This route is only accessible if the user has a valid access_token.
	mux.Handle("/api/messages/protected", common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("in /api/messages/protected r", r)
			fmt.Println("in /api/messages/protected")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message":"Hello from a private endpoint! You need to be authenticated to see this."}`))
		}),
	))

	// mux.Handle("/v0.1/parties", common.AddMiddleware(pp, common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

	mux.Handle("/v0.1/parties", common.AddMiddleware(hrlParty.RateLimit(pp), common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"parties:cud", "parties:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

	// mux.Handle("/v0.1/parties", common.AddMiddleware(pp, common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"read:admin-messages"}))

	// mux.Handle("/v0.1/parties/", common.AddMiddleware(pp, common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain)))
	mux.Handle("/v0.1/parties/", common.AddMiddleware(hrlParty.RateLimit(pp), common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"parties:cud", "parties:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

	/*mux.Handle("/v0.1/users", common.AddMiddleware(usc,
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

	mux.Handle("/v0.1/users/", common.AddMiddleware(usc,
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))*/

	return nil
}

// InitTest the party controllers
func InitTest(log *zap.Logger, rateOpt *config.RateOptions, jwtOpt *config.JWTOptions, mux *http.ServeMux, store *goredisstore.GoRedisStore, serverOpt *config.ServerOptions, grpcServerOpt *config.GrpcServerOptions, uptraceOpt *config.UptraceOptions, configFilePath string) error {
	pwd, _ := os.Getwd()
	keyPath := filepath.Join(pwd, filepath.FromSlash("/../../../")+filepath.FromSlash(grpcServerOpt.GrpcCaCertPath))
	creds, err := credentials.NewClientTLSFromFile(keyPath, "localhost")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
	}

	/*tracer, _ := interceptors.NewJaegerTracer(log, jaegerTracerOpt, jaegerTracerOpt.UserServiceName)
	userconn, err := grpc.NewClient(grpcServerOpt.GrpcUserServerPort, grpc.WithUserAgent(jaegerTracerOpt.UserAgent), grpc.WithTransportCredentials(creds), grpc.WithUnaryInterceptor(grpc_opentracing.UnaryClientInterceptor(grpc_opentracing.WithTracer(tracer))))
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 113), zap.Error(err))
		return err
	}*/

	tp, err := config.InitTracerProvider()
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 9108), zap.Error(err))
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Error("Error", zap.Int("msgnum", 9108), zap.Error(err))
		}
	}()

	userconn, err := grpc.NewClient(grpcServerOpt.GrpcUserServerPort, grpc.WithTransportCredentials(creds), grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 113), zap.Error(err))
		return err
	}

	// Set up a connection to the server.
	/*tracer1, _ := interceptors.NewJaegerTracer(log, jaegerTracerOpt, jaegerTracerOpt.PartyServiceName)
	partyconn, err := grpc.NewClient(grpcServerOpt.GrpcPartyServerPort, grpc.WithUserAgent(jaegerTracerOpt.UserAgent), grpc.WithTransportCredentials(creds), grpc.WithUnaryInterceptor(grpc_opentracing.UnaryClientInterceptor(grpc_opentracing.WithTracer(tracer1))))
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
		return err
	}*/

	partyconn, err := grpc.NewClient(grpcServerOpt.GrpcPartyServerPort, grpc.WithTransportCredentials(creds), grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
		return err
	}

	h.SetupServiceConfig(configFilePath)
	workflowClient, err = h.Builder.BuildCadenceClient()
	if err != nil {
		panic(err)
	}

	u := partyproto.NewUserServiceClient(userconn)
	p := partyproto.NewPartyServiceClient(partyconn)
	// uc := NewUController(log, u, h, workflowClient)
	usc := NewUserController(log, u, h, workflowClient)
	pp := NewPartyController(log, p, u)

	hrlParty := common.GetHTTPRateLimiter(store, rateOpt.PartyMaxRate, rateOpt.PartyMaxBurst)
	// hrlUser := common.GetHTTPRateLimiter(store, rateOpt.UserMaxRate, rateOpt.UserMaxBurst)
	// hrlU := common.GetHTTPRateLimiter(store, rateOpt.UMaxRate, rateOpt.UMaxBurst)

	mux.Handle("/v0.1/parties", common.AddMiddleware(hrlParty.RateLimit(pp), common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"parties:cud", "parties:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

	mux.Handle("/v0.1/parties/", common.AddMiddleware(hrlParty.RateLimit(pp), common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"parties:cud", "parties:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

	/*mux.Handle("/v0.1/users", common.AddMiddleware(hrlUser.RateLimit(usc),
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

	mux.Handle("/v0.1/users/", common.AddMiddleware(hrlUser.RateLimit(usc),
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))*/

	/* handler := http.HandlerFunc(usc.GetUsers)

	 mux.Handle("GET /v0.1/users", common.AddMiddleware(handler,
	common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))*/

	/*mux.Handle("GET /v0.1/users", common.AddMiddleware(hrlUser.RateLimit(usc),
	common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))*/

	// mux.Handle("GET /v0.1/users", middlewareChain(usc.GetUsers))

	// Chain middlewares
	umiddlewareChain1 := chainMiddlewares(
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain),
		common.ValidatePermissions([]string{"users:cud"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain),
	)

	umiddlewareChain2 := chainMiddlewares(
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain),
		common.ValidatePermissions([]string{"users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain),
	)

	mux.Handle("GET /v0.1/users", umiddlewareChain2(http.HandlerFunc(usc.GetUsers)))

	mux.Handle("GET /v0.1/users/{id}", umiddlewareChain2(http.HandlerFunc(usc.GetUser)))

	mux.Handle("POST /v0.1/users/change-password", umiddlewareChain1(http.HandlerFunc(usc.ChangePassword)))

	mux.Handle("POST /v0.1/users/getuserbyemail", umiddlewareChain2(http.HandlerFunc(usc.GetUserByEmail)))

	mux.Handle("PUT /v0.1/users/{id}", umiddlewareChain1(http.HandlerFunc(usc.UpdateUser)))

	mux.Handle("DELETE /v0.1/users/{id}", umiddlewareChain1(http.HandlerFunc(usc.DeleteUser)))

	/*
		   mux.Handle("GET /v0.1/users", common.AddMiddleware(http.HandlerFunc(usc.GetUsers),
				common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

		  mux.Handle("GET /v0.1/users/{id}", common.AddMiddleware(http.HandlerFunc(usc.GetUser),
				common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

			mux.Handle("POST /v0.1/users/change-password", common.AddMiddleware(http.HandlerFunc(usc.ChangePassword),
				common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

			mux.Handle("POST /v0.1/users/getuserbyemail", common.AddMiddleware(http.HandlerFunc(usc.GetUserByEmail),
				common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

			mux.Handle("PUT /v0.1/users/{id}", common.AddMiddleware(http.HandlerFunc(usc.UpdateUser),
				common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))

			mux.Handle("DELETE /v0.1/users/{id}", common.AddMiddleware(http.HandlerFunc(usc.DeleteUser),
				common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"users:cud", "users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))*/

	return nil
}

func chainMiddlewares(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(finalHandler http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			finalHandler = middlewares[i](finalHandler)
		}
		return finalHandler
	}
}
