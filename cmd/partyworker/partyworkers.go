package main

import (
	//"flag"
	//"time"

	"context"
	"os"
	"path/filepath"

	//"github.com/pborman/uuid"
	//"go.uber.org/cadence/client"
	"github.com/prov100/dc1/internal/config"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.uber.org/cadence/worker"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

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

func main() {
	v, err := config.GetViper()
	if err != nil {
		os.Exit(1)
	}

	configFilePath := v.GetString("SC_DCSA_WORKFLOW_CONFIG_FILE_PATH")

	var h common.WfHelper
	h.SetupServiceConfig(configFilePath)

	logOpt, err := config.GetLogConfig(v)
	if err != nil {
		os.Exit(1)
	}

	log := config.SetUpLogging(logOpt.Path)

	_, _, _, grpcServerOpt, _, _, _ := config.GetConfigOpt(log, v)
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 103),
			zap.Error(err))
		os.Exit(1)
	}

	pwd, _ := os.Getwd()
	keyPath := pwd + filepath.FromSlash(grpcServerOpt.GrpcCaCertPath)
	creds, err := credentials.NewClientTLSFromFile(keyPath, "localhost")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 110), zap.Error(err))
	}

	/*tracer, _ := interceptors.NewJaegerTracer(log, jaegerTracerOpt, jaegerTracerOpt.UserServiceName)

	userconn, err := grpc.NewClient(grpcServerOpt.GrpcUserServerPort, grpc.WithUserAgent(jaegerTracerOpt.UserAgent), grpc.WithTransportCredentials(creds), grpc.WithUnaryInterceptor(grpc_opentracing.UnaryClientInterceptor(grpc_opentracing.WithTracer(tracer))))
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 103),
			zap.Error(err))
		os.Exit(1)
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
		log.Error("Error",
			zap.Error(err))
		os.Exit(1)
	}
	userServiceClient := partyproto.NewUserServiceClient(userconn)
	activities1 := &userworkflows.Activities1{UserServiceClient: userServiceClient}
	// User Service

	/*h.RegisterWorkflow(workflows.ListWorkflow)
	h.RegisterActivity(activities.ListActivity)
	h.RegisterWorkflow(workflows.CreateWorkflow)
	h.RegisterActivity(activities.CreateActivity)
	h.RegisterWorkflow(workflows.ActionWorkflow)
	h.RegisterActivity(activities.ActionActivity)
	h.RegisterWorkflow(workflows.StatusWorkflow)
	h.RegisterActivity(activities.StatusActivity)
	h.RegisterWorkflow(workflows.GetUserWorkflow)
	h.RegisterActivity(activities.GetUserActivity)
	h.RegisterWorkflow(workflows.GetUsersWorkflow)
	h.RegisterActivity(activities.GetUsersActivity)
	h.RegisterWorkflow(workflows.GetUserByEmailWorkflow)
	h.RegisterActivity(activities.GetUserByEmailActivity)*/
	h.RegisterWorkflow(userworkflows.UpdateUserWorkflow)
	// h.RegisterWorkflow(userworkflows.CreateUserWorkflow)
	// h.RegisterActivity(activities.UpdateUserActivity)
	h.RegisterActivity(activities1)
	// h.RegisterWorkflow(workflows.DeleteUserWorkflow)
	// h.RegisterActivity(activities.DeleteUserActivity)

	startWorkers(&h)

	// The workers are supposed to be long running process that should not exit.
	// Use select{} to block indefinitely for samples, you can quit by CMD+C.
	select {}
}
