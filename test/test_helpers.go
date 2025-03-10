package test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"

	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/jmoiron/sqlx"
	"github.com/prov100/dc1/internal/common"
	"go.uber.org/zap"
)

// GetUUIDDateValues -- data for tests
func GetUUIDDateValues(log *zap.Logger) ([]byte, string, *timestamp.Timestamp, *timestamp.Timestamp, string, string, string, string, error) {
	uuid4, err := common.GetUUIDBytes()
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8053), zap.Error(err))
		return nil, "", nil, nil, "", "", "", "", err
	}

	ttime := common.GetTimeDetails()
	tn := common.TimeToTimestamp(ttime)

	uuid4Str, err := common.UUIDBytesToStr(uuid4)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8055), zap.Error(err))
		return nil, "", nil, nil, "", "", "", "", err
	}
	uuid4StrJSON, _ := json.Marshal(uuid4Str)
	uuid4JSON, _ := json.Marshal(uuid4)
	createdAtJSON, _ := json.Marshal(tn)
	updatedAtJSON, _ := json.Marshal(tn)
	return uuid4, uuid4Str, tn, tn, string(uuid4JSON), string(uuid4StrJSON), string(createdAtJSON), string(updatedAtJSON), nil
}

// LoadSQL -- drop db, create db, use db, load data
func LoadSQL(log *zap.Logger, dbService *common.DBService) error {
	var err error
	ctx := context.Background()

	if dbService.DBType == common.DBMysql {
		err = execSQLFile(ctx, log, dbService.MySQLTruncateFilePath, dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8056), zap.Error(err))
			return err
		}
		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/vessels.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/locations.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/bookings.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/commodities.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/reference1.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/value_added_service_requests.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/requested_equipments.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/shipment_locations.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/carriers.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/carrier_clauses.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/seals.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/shipments.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/shipment_cutoff_times.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/shipping_instructions.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/equipments.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/utilized_transport_equipments.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/transports.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/transport_documents.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/consignment_items.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/cargo_items.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/cargo_line_items.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/operations_events.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/transport_events.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/shipment_events.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/equipment_events.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/parties.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/party_contact_details.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/party_identifying_codes.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/users.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/addresses.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/charges.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/displayed_addresses.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/document_parties.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/facilities.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/iso_equipment_codes.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/services.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/service_schedules.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/shipment_carrier_clauses.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/transport_calls.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/vessel_schedules.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/voyages.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/shipment_transports.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.MySQLTestFilePath+"/timestamps.sql", dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8057), zap.Error(err))
			return err
		}

	} else if dbService.DBType == common.DBPgsql {
		err = execSQLFile(ctx, log, dbService.PgSQLTruncateFilePath, dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8058), zap.Error(err))
			return err
		}

		err = execSQLFile(ctx, log, dbService.PgSQLTestFilePath, dbService.DB)
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 8059), zap.Error(err))
			return err
		}
	}

	return nil
}

func execSQLFile(ctx context.Context, log *zap.Logger, sqlFilePath string, db *sqlx.DB) error {
	content, err := os.ReadFile(sqlFilePath)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8060), zap.Error(err))
		return err
	}

	tx, err := db.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8061), zap.Error(err))
	}

	sqlLines := strings.Split(string(content), ";\n")
	for _, sqlLine := range sqlLines {
		if sqlLine != "" {
			_, err := tx.ExecContext(ctx, sqlLine)
			if err != nil {
				log.Error("Error", zap.Int("msgnum", 8062), zap.Error(err))
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					log.Error("Error", zap.Int("msgnum", 8063), zap.Error(rollbackErr))
					return err
				}
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 8063), zap.Error(err))
		return err
	}
	return nil
}
