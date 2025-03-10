package main

import (
	"os"

	_ "github.com/go-sql-driver/mysql" // mysql
	"github.com/prov100/dc1/internal/common"
	"github.com/prov100/dc1/internal/config"
	"github.com/prov100/dc1/internal/services/partyservices"
	"go.uber.org/zap"
)

func main() {
	v, err := config.GetViper()
	if err != nil {
		os.Exit(1)
	}

	logOpt, err := config.GetLogConfig(v)
	if err != nil {
		os.Exit(1)
	}

	log := config.SetUpLogging(logOpt.PartyPath)

	dbOpt, err := config.GetDbConfig(log, v, false, "SC_DCSA_DB", "SC_DCSA_DBHOST", "SC_DCSA_DBPORT", "SC_DCSA_DBUSER", "SC_DCSA_DBPASS", "SC_DCSA_DBNAME", "", "", "", "", "", "")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 103), zap.Error(err))
		os.Exit(1)
	}

	jwtOpt, err := config.GetJWTConfig(log, v, false, "SC_DCSA_JWT_KEY", "SC_DCSA_JWT_DURATION")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 103), zap.Error(err))
		os.Exit(1)
	}

	/*elasticOpt, err := config.GetElasticConfig(log, v, false, "SC_DCSA_ELASTIC_USER", "SC_DCSA_ELASTIC_PASS", "SC_DCSA_ELASTIC_SERVER", "SC_DCSA_ELASTIC_INDEXNAME")
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 103), zap.Error(err))
		os.Exit(1)
	}*/

	redisOpt, mailerOpt, _, grpcServerOpt, oauthOpt, userOpt, uptraceOpt := config.GetConfigOpt(log, v)

	dbService, redisService, mailerService := common.GetServices(log, false, dbOpt, redisOpt, jwtOpt, mailerOpt)

	pwd, _ := os.Getwd()
	partyservices.StartPartyServer(log, false, pwd, dbOpt, redisOpt, mailerOpt, grpcServerOpt, jwtOpt, oauthOpt, userOpt, uptraceOpt, dbService, redisService, mailerService)
}
