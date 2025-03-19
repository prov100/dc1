package partycontrollers

import (
	"context"
	"fmt"

	//"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/prov100/dc1/internal/common"
	"github.com/prov100/dc1/internal/config"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"

	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"

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
	fmt.Println("internal/controllers/partycontrollers/init.go Init() started")
	fmt.Println("internal/controllers/partycontrollers/init.go Init() started mux is", mux)
	pwd, _ := os.Getwd()
	keyPath := pwd + filepath.FromSlash(grpcServerOpt.GrpcCaCertPath)

	u, p, h, workflowClient, err := initSetup(log, keyPath, configFilePath, serverOpt, grpcServerOpt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
		return err
	}

	initUsers(mux, serverOpt, log, u, h, workflowClient)
	initParties(mux, serverOpt, log, u, p, h, workflowClient)
	fmt.Println("internal/controllers/partycontrollers/init.go Init() ended")
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
	fmt.Println("internal/controllers/partycontrollers/init.go initSetup() started")
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
	fmt.Println("internal/controllers/partycontrollers/init.go initSetup() ended")
	return u, p, h, workflowClient, nil
}

func initParties(mux *http.ServeMux, serverOpt *config.ServerOptions, log *zap.Logger, u partyproto.UserServiceClient, p partyproto.PartyServiceClient, wfHelper common.WfHelper, workflowClient client.Client) {
	fmt.Println("internal/controllers/partycontrollers/init.go initParties() started")
	/*pp := NewPartyController(log, p, u)

	mux.Handle("GET /v0.1/parties", mChainRead(http.HandlerFunc(pp.GetParties)))

	mux.Handle("POST /v0.1/parties/{id}", mChainCud(http.HandlerFunc(pp.CreateParty)))*/
	fmt.Println("internal/controllers/partycontrollers/init.go initParties() ended")
}

func initUsers(mux *http.ServeMux, serverOpt *config.ServerOptions, log *zap.Logger, u partyproto.UserServiceClient, wfHelper common.WfHelper, workflowClient client.Client) {
	fmt.Println("internal/controllers/partycontrollers/init.go initUsers() started")
	fmt.Println("internal/controllers/partycontrollers/init.go initUsers() started mux is", mux)
	usc := NewUserController(log, u, h, workflowClient, serverOpt)

	mux.Handle("GET /v0.1/users", http.HandlerFunc(usc.GetUsers))
	mux.Handle("GET /v0.1/users/{id}", http.HandlerFunc(usc.GetUser))
	mux.Handle("POST /v0.1/users/getuserbyemail", http.HandlerFunc(usc.GetUserByEmail))

	fmt.Println("internal/controllers/partycontrollers/init.go initUsers() ended")

	/*mux.Handle("GET /v0.1/users", mChainRead(http.HandlerFunc(usc.GetUsers)))

	mux.Handle("GET /v0.1/users/{id}", mChainRead(http.HandlerFunc(usc.GetUser)))

	mux.Handle("POST /v0.1/users/change-password", mChainCud(http.HandlerFunc(usc.ChangePassword)))

	mux.Handle("POST /v0.1/users/getuserbyemail", mChainRead(http.HandlerFunc(usc.GetUserByEmail)))

	mux.Handle("PUT /v0.1/users/{id}", mChainCud(http.HandlerFunc(usc.UpdateUser)))

	mux.Handle("DELETE /v0.1/users/{id}", mChainCud(http.HandlerFunc(usc.DeleteUser)))*/
}
