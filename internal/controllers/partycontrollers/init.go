package partycontrollers

import (
	"context"
	//"fmt"
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
func Init(log *zap.Logger, mux *http.ServeMux, store *goredisstore.GoRedisStore, serverOpt *config.ServerOptions, grpcServerOpt *config.GrpcServerOptions, uptraceOpt *config.UptraceOptions, configFilePath string) error {
	pwd, _ := os.Getwd()
	keyPath := pwd + filepath.FromSlash(grpcServerOpt.GrpcCaCertPath)

	u, p, h, workflowClient, err := initSetup(log, keyPath, configFilePath, serverOpt, grpcServerOpt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
		return err
	}

	initUsers(mux, serverOpt, log, u, h, workflowClient)
	initParties(mux, serverOpt, log, u, p, h, workflowClient)

	/*h.SetupServiceConfig(configFilePath)
	var err error
	workflowClient, err = h.Builder.BuildCadenceClient()
	if err != nil {
		panic(err)
	}


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
	mux.Handle("/v0.1/parties/", common.AddMiddleware(hrlParty.RateLimit(pp), common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain), common.ValidatePermissions([]string{"parties:cud", "parties:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain)))*/

	return nil
}

// InitTest the party controllers
func InitTest(log *zap.Logger, mux *http.ServeMux, store *goredisstore.GoRedisStore, serverOpt *config.ServerOptions, grpcServerOpt *config.GrpcServerOptions, uptraceOpt *config.UptraceOptions, configFilePath string) error {
	pwd, _ := os.Getwd()
	keyPath := filepath.Join(pwd, filepath.FromSlash("/../../../")+filepath.FromSlash(grpcServerOpt.GrpcCaCertPath))

	u, p, h, workflowClient, err := initSetup(log, keyPath, configFilePath, serverOpt, grpcServerOpt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
		return err
	}

	initUsers(mux, serverOpt, log, u, h, workflowClient)
	initParties(mux, serverOpt, log, u, p, h, workflowClient)

	return nil
}

func initSetup(log *zap.Logger, keyPath string, configFilePath string, serverOpt *config.ServerOptions, grpcServerOpt *config.GrpcServerOptions) (partyproto.UserServiceClient, partyproto.PartyServiceClient, common.WfHelper, client.Client, error) {
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

	h.SetupServiceConfig(configFilePath)
	workflowClient, err = h.Builder.BuildCadenceClient()
	if err != nil {
		panic(err)
	}

	userconn, err := grpc.NewClient(grpcServerOpt.GrpcUserServerPort, grpc.WithTransportCredentials(creds), grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 113), zap.Error(err))
		return nil, nil, h, nil, err
	}

	u := partyproto.NewUserServiceClient(userconn)

	partyconn, err := grpc.NewClient(grpcServerOpt.GrpcPartyServerPort, grpc.WithTransportCredentials(creds), grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
		return nil, nil, h, nil, err
	}

	p := partyproto.NewPartyServiceClient(partyconn)

	return u, p, h, workflowClient, nil
}

func initParties(mux *http.ServeMux, serverOpt *config.ServerOptions, log *zap.Logger, u partyproto.UserServiceClient, p partyproto.PartyServiceClient, wfHelper common.WfHelper, workflowClient client.Client) {
	/*pp := NewPartyController(log, p, u)

	mChainCud := common.ChainMiddlewares(
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain),
		common.ValidatePermissions([]string{"parties:cud"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain),
	)

	mChainRead := common.ChainMiddlewares(
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain),
		common.ValidatePermissions([]string{"parties:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain),
	)

	mux.Handle("GET /v0.1/parties", mChainRead(http.HandlerFunc(pp.GetParties)))

	mux.Handle("POST /v0.1/parties/{id}", mChainCud(http.HandlerFunc(pp.CreateParty)))*/
}

func initUsers(mux *http.ServeMux, serverOpt *config.ServerOptions, log *zap.Logger, u partyproto.UserServiceClient, wfHelper common.WfHelper, workflowClient client.Client) {
	usc := NewUserController(log, u, h, workflowClient)
	// Chain middlewares
	mChainCud := common.ChainMiddlewares(
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain),
		common.ValidatePermissions([]string{"users:cud"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain),
	)

	mChainRead := common.ChainMiddlewares(
		common.EnsureValidToken(serverOpt.Auth0Audience, serverOpt.Auth0Domain),
		common.ValidatePermissions([]string{"users:read"}, serverOpt.Auth0Audience, serverOpt.Auth0Domain),
	)

	mux.Handle("GET /v0.1/users", mChainRead(http.HandlerFunc(usc.GetUsers)))

	mux.Handle("GET /v0.1/users/{id}", mChainRead(http.HandlerFunc(usc.GetUser)))

	mux.Handle("POST /v0.1/users/change-password", mChainCud(http.HandlerFunc(usc.ChangePassword)))

	mux.Handle("POST /v0.1/users/getuserbyemail", mChainRead(http.HandlerFunc(usc.GetUserByEmail)))

	mux.Handle("PUT /v0.1/users/{id}", mChainCud(http.HandlerFunc(usc.UpdateUser)))

	mux.Handle("DELETE /v0.1/users/{id}", mChainCud(http.HandlerFunc(usc.DeleteUser)))
}
