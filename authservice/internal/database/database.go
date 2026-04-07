package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/obot-platform/discobot/authservice/internal/config"
	"github.com/obot-platform/discobot/authservice/internal/model"
)

type DB struct {
	*gorm.DB
	ReadDB *gorm.DB
	Driver string
}

func New(cfg *config.Config) (*DB, error) {
	slowLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	dsn := cfg.CleanDSN()
	switch cfg.DatabaseDriver {
	case "sqlite":
		return newSQLite(dsn, slowLogger)
	case "postgres":
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: slowLogger})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
		sqlDB, err := db.DB()
		if err != nil {
			return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
		}
		sqlDB.SetMaxOpenConns(25)
		sqlDB.SetMaxIdleConns(5)
		return &DB{DB: db, Driver: "postgres"}, nil
	default:
		return nil, fmt.Errorf("unsupported driver: %s", cfg.DatabaseDriver)
	}
}

func newSQLite(dsn string, dbLogger logger.Interface) (*DB, error) {
	rawPath := strings.TrimPrefix(dsn, "file:")
	isMemory := rawPath == ":memory:" || strings.HasPrefix(rawPath, ":memory:")

	if !isMemory {
		dir := filepath.Dir(rawPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
		}
	}

	baseDSN := rawPath
	if !isMemory {
		baseDSN = "file:" + rawPath
	}

	basePragmas := []string{
		"_pragma=journal_mode(WAL)",
		"_pragma=busy_timeout(5000)",
		"_pragma=foreign_keys(1)",
		"_pragma=synchronous(NORMAL)",
	}

	appendParams := func(base string, params []string) string {
		sep := "?"
		if strings.Contains(base, "?") {
			sep = "&"
		}
		return base + sep + strings.Join(params, "&")
	}

	writeParams := append(basePragmas, "_txlock=immediate")
	if !isMemory {
		writeParams = append(writeParams, "mode=rwc")
	}
	writeDSN := appendParams(baseDSN, writeParams)
	writeDB, err := gorm.Open(sqlite.Open(writeDSN), &gorm.Config{Logger: dbLogger})
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite write pool: %w", err)
	}
	writeSQLDB, err := writeDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get write pool sql.DB: %w", err)
	}
	writeSQLDB.SetMaxOpenConns(1)
	writeSQLDB.SetMaxIdleConns(1)

	if isMemory {
		return &DB{DB: writeDB, Driver: "sqlite"}, nil
	}

	readParams := append(basePragmas, "mode=ro", "_pragma=query_only(1)")
	readDSN := appendParams(baseDSN, readParams)
	readDB, err := gorm.Open(sqlite.Open(readDSN), &gorm.Config{Logger: dbLogger})
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite read pool: %w", err)
	}
	readSQLDB, err := readDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get read pool sql.DB: %w", err)
	}
	readSQLDB.SetMaxOpenConns(25)
	readSQLDB.SetMaxIdleConns(4)

	return &DB{DB: writeDB, ReadDB: readDB, Driver: "sqlite"}, nil
}

func (db *DB) Migrate() error {
	return db.AutoMigrate(model.AllModels()...)
}

func (db *DB) Close() error {
	writeSQLDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	if err := writeSQLDB.Close(); err != nil {
		return err
	}
	if db.ReadDB != nil {
		readSQLDB, err := db.ReadDB.DB()
		if err != nil {
			return err
		}
		return readSQLDB.Close()
	}
	return nil
}
