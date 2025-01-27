package main

import (
	//"flag"
	//"time"

	"os"

	//"github.com/pborman/uuid"
	//"go.uber.org/cadence/client"
	"github.com/prov100/dc1/internal/config"
	"github.com/prov100/dc1/internal/workers/userworkers"
	"go.uber.org/zap"
	// workflows "github.com/prov100/dc1/internal/controllers/partycontrollers"
)

// This needs to be done as part of a bootstrap step when the process starts.
// The workers are supposed to be long running.
/*func startWorkers(h *common.WfHelper) {
	// Configure worker options.
	workerOptions := worker.Options{
		MetricsScope: h.WorkerMetricScope,
		Logger:       h.Logger,
	}
	h.StartWorkers(h.Config.DomainName, partycontrollers.ApplicationName, workerOptions)
}*/

func main() {
	v, err := config.GetViper()
	if err != nil {
		os.Exit(1)
	}

	configFilePath := v.GetString("SC_DCSA_WORKFLOW_CONFIG_FILE_PATH")

	logOpt, err := config.GetLogConfig(v)
	if err != nil {
		os.Exit(1)
	}

	log := config.SetUpLogging(logOpt.Path)

	_, _, _, grpcServerOpt, _, _, uptraceOpt := config.GetConfigOpt(log, v)
	if err != nil {
		log.Error("Error",
			zap.Int("msgnum", 103),
			zap.Error(err))
		os.Exit(1)
	}

	pwd, _ := os.Getwd()

	userworkers.StartUserWorker(log, false, pwd, grpcServerOpt, uptraceOpt, configFilePath)
}
