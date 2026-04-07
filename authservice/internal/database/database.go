package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/obot-platform/discobot/authservice/internal/config"
	"github.com/obot-platform/discobot/authservice/internal/model"
)

type DB struct {
	*gorm.DB
}

func New(cfg *config.Config) (*DB, error) {
	dsn := cfg.CleanDSN()
	switch cfg.DatabaseDriver {
	case "sqlite":
		rawPath := strings.TrimPrefix(dsn, "file:")
		if rawPath != ":memory:" {
			if err := os.MkdirAll(filepath.Dir(rawPath), 0o755); err != nil {
				return nil, fmt.Errorf("failed to create sqlite db dir: %w", err)
			}
		}
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
		if err != nil {
			return nil, err
		}
		return &DB{DB: db}, nil
	case "postgres":
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			return nil, err
		}
		return &DB{DB: db}, nil
	default:
		return nil, fmt.Errorf("unsupported driver: %s", cfg.DatabaseDriver)
	}
}

func (db *DB) Migrate() error {
	return db.AutoMigrate(model.AllModels()...)
}
