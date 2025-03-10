package common

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/reflectx"
	"github.com/prov100/dc1/internal/config"
	"go.uber.org/zap"
)

// DBIntf - Interface to the Database
type DBIntf interface {
	DBClose() error
}

// DBService - Database type and Pointer to access Db
type DBService struct {
	DBType                string
	DB                    *sqlx.DB
	Schema                string
	LimitSQLRows          string
	MySQLTestFilePath     string
	MySQLSchemaFilePath   string
	MySQLTruncateFilePath string
	PgSQLTestFilePath     string
	PgSQLSchemaFilePath   string
	PgSQLTruncateFilePath string
	log                   *zap.Logger
}

// NewDBService - get connection to DB and create a DBService struct
func NewDBService(log *zap.Logger, dbOpt *config.DBOptions) (*DBService, error) {
	var db *sqlx.DB
	var err error

	if dbOpt.DB == DBMysql {
		fmt.Println("common/dbservice.go:NewDBService started dbOpt.DB is", dbOpt.DB)
		fmt.Println("common/dbservice.go:NewDBService started connection string is", fmt.Sprint(dbOpt.User, ":", dbOpt.Password, "@tcp(", dbOpt.Host,
			":", dbOpt.Port, ")/", dbOpt.Schema, "?charset=utf8mb4&parseTime=True"))

		db, err = sqlx.Open(dbOpt.DB, fmt.Sprint(dbOpt.User, ":", dbOpt.Password, "@tcp(", dbOpt.Host,
			":", dbOpt.Port, ")/", dbOpt.Schema, "?charset=utf8mb4&parseTime=True"))
		if err != nil {
			log.Error("Error", zap.Int("msgnum", 500), zap.Error(err))
			return nil, err
		}
	} else if dbOpt.DB == DBPgsql {
		log.Info("Pgsql")
	}

	fmt.Println("common/dbservice.go:NewDBService() started")
	fmt.Println("common/dbservice.go:NewDBService() started db is", db)

	// make sure connection is available
	/*err = db.Ping()
	fmt.Println("db Ping() err", err)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 501), zap.Error(err))
		return nil, err
	}
	fmt.Println("after db Ping() db is", db)*/
	fmt.Println("common/dbservice.go:NewDBService started db is", db)
	db.Mapper = reflectx.NewMapperFunc("json", strings.ToLower)

	dbService := &DBService{}
	dbService.DBType = dbOpt.DB
	dbService.DB = db
	dbService.Schema = dbOpt.Schema
	dbService.LimitSQLRows = dbOpt.LimitSQLRows
	dbService.MySQLTestFilePath = dbOpt.MySQLTestFilePath
	dbService.MySQLSchemaFilePath = dbOpt.MySQLSchemaFilePath
	dbService.MySQLTruncateFilePath = dbOpt.MySQLTruncateFilePath
	dbService.PgSQLTestFilePath = dbOpt.PgSQLTestFilePath
	dbService.PgSQLSchemaFilePath = dbOpt.PgSQLSchemaFilePath
	dbService.PgSQLTruncateFilePath = dbOpt.PgSQLTruncateFilePath
	dbService.log = log

	return dbService, nil
}

// DBClose - Close connection to database
func (dbService *DBService) DBClose() error {
	err := dbService.DB.Close()
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 502), zap.Error(err))
		return err
	}
	return nil
}

// CreateDBService -- init DB
func CreateDBService(log *zap.Logger, dbOpt *config.DBOptions) (*DBService, error) {
	dbService, err := NewDBService(log, dbOpt)
	if err != nil {
		log.Error("Error", zap.Int("msgnum", 750), zap.Error(err))
		return nil, err
	}
	return dbService, nil
}

type execFunc func(*sqlx.Tx) error

// InsUpd - Insert, Update to database
func (dbService *DBService) InsUpd(ctx context.Context, userEmail string, requestID string, ex execFunc) error {
	tx, err := dbService.DB.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 510), zap.Error(err))
		return err
	}

	err = ex(tx)
	if err != nil {
		dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 511), zap.Error(err))
		err = tx.Rollback()
		if err != nil {
			dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 512), zap.Error(err))
			return err
		}
		dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 513), zap.Error(err))
		return err
	}

	err = tx.Commit()
	if err != nil {
		dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 514), zap.Error(err))
		err = tx.Rollback()
		if err != nil {
			dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 515), zap.Error(err))
			return err
		}
	}

	return nil
}

// ScanFunc - process row
type ScanFunc func(dest ...interface{}) error

// EachRowFunc - scan a row
type EachRowFunc func(row ScanFunc) error

// PartialQuery - function to drive the loop
type PartialQuery func(row EachRowFunc) error

// QueryRow - Query a single row
func (dbService *DBService) QueryRow(ctx context.Context, userEmail string, requestID string, query string, args ...interface{}) PartialQuery {
	return func(row EachRowFunc) error {
		aRow := dbService.DB.QueryRowContext(ctx, query, args...)
		err := row(aRow.Scan)
		switch {
		case err == sql.ErrNoRows:
			dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 520), zap.Error(err))
		case err != nil:
			dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 521), zap.Error(err))
		default:
		}

		return err
	}
}

// QueryRows - query multiple rows
func (dbService *DBService) QueryRows(ctx context.Context, userEmail string, requestID string, query string, args ...interface{}) PartialQuery {
	return func(row EachRowFunc) error {
		rows, err := dbService.DB.QueryContext(ctx, query, args...)
		if err != nil {
			dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 525), zap.Error(err))
			err = rows.Close()
			if err != nil {
				dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 525), zap.Error(err))
				return err
			}
			return err
		}
		for rows.Next() {
			err = row(rows.Scan)
			if err != nil {
				log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 4504), zap.Error(err))
				err = rows.Close()
				if err != nil {
					dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 525), zap.Error(err))
					return err
				}
				return err
			}
		}
		err = rows.Close()
		if err != nil {
			dbService.log.Error("Error", zap.String("user", userEmail), zap.String("reqid", requestID), zap.Int("msgnum", 525), zap.Error(err))
			return err
		}
		return nil
	}
}
