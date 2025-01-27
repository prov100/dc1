package userworkers

import (
	//"flag"
	//"time"

	"context"
	"os"

	//"github.com/pborman/uuid"
	//"go.uber.org/cadence/client"
	"github.com/prov100/dc1/internal/config"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.uber.org/cadence/worker"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/prov100/dc1/internal/common"
	userworkflows "github.com/prov100/dc1/internal/workflows/userworkflows"

	// workflows "github.com/prov100/dc1/internal/controllers/partycontrollers"
	// interceptors "github.com/prov100/dc1/internal/interceptors"
	partyproto "github.com/prov100/dc1/internal/protogen/party/v1"
)

// This needs to be done as part of a bootstrap step when the process starts.
// The workers are supposed to be long running.
func startWorkers(h *common.WfHelper) {
	// Configure worker options.
	workerOptions := worker.Options{
		MetricsScope: h.WorkerMetricScope,
		Logger:       h.Logger,
	}
	h.StartWorkers(h.Config.DomainName, userworkflows.ApplicationName, workerOptions)
}

func StartUserWorker(log *zap.Logger, isTest bool, pwd string, grpcServerOpt *config.GrpcServerOptions, uptraceOpt *config.UptraceOptions, configFilePath string) {
	var h common.WfHelper
	h.SetupServiceConfig(configFilePath)

	/*keyPath := pwd + filepath.FromSlash(grpcServerOpt.GrpcCaCertPath)
	creds, err := credentials.NewClientTLSFromFile(keyPath, "localhost")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
	}*/

	creds, err := common.GetClientCred(log, isTest, pwd, grpcServerOpt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
		os.Exit(1)
	}

	// tracer, _ := interceptors.NewJaegerTracer(log, jaegerTracerOpt, jaegerTracerOpt.UserServiceName)

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
		log.Error("Error",
			zap.Error(err))
		os.Exit(1)
	}
	userServiceClient := partyproto.NewUserServiceClient(userconn)
	activities1 := &userworkflows.Activities1{UserServiceClient: userServiceClient}
	// User Service

	h.RegisterWorkflow(userworkflows.UpdateUserWorkflow)
	// h.RegisterWorkflow(userworkflows.CreateUserWorkflow)
	h.RegisterActivity(activities1)

	startWorkers(&h)

	// The workers are supposed to be long running process that should not exit.
	// Use select{} to block indefinitely for samples, you can quit by CMD+C.
	select {}
}
