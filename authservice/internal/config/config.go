package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/xdg"
)

type Config struct {
	Port                 int
	DatabaseDSN          string
	DatabaseDriver       string
	PublicHostname       string
	GoogleClientID       string
	GoogleClientSecret   string
	GitHubClientID       string
	GitHubClientSecret   string
	BrowserSessionTTL    time.Duration
	AuthorizationCodeTTL time.Duration
	AccessTokenTTL       time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{}
	cfg.Port = getEnvInt("PORT", 3010)
	cfg.DatabaseDSN = getEnv("DATABASE_DSN", "sqlite3://"+filepath.Join(xdg.DataHome, "discobot", "discobot-auth.db"))
	cfg.DatabaseDriver = detectDriver(cfg.DatabaseDSN)
	cfg.PublicHostname = getEnv("PUBLIC_HOSTNAME", "")
	cfg.GoogleClientID = getEnv("GOOGLE_CLIENT_ID", "")
	cfg.GoogleClientSecret = getEnv("GOOGLE_CLIENT_SECRET", "")
	cfg.GitHubClientID = getEnv("GITHUB_CLIENT_ID", "")
	cfg.GitHubClientSecret = getEnv("GITHUB_CLIENT_SECRET", "")
	cfg.BrowserSessionTTL = getEnvDuration("BROWSER_SESSION_TTL", 24*time.Hour)
	cfg.AuthorizationCodeTTL = getEnvDuration("AUTHORIZATION_CODE_TTL", 5*time.Minute)
	cfg.AccessTokenTTL = getEnvDuration("ACCESS_TOKEN_TTL", 15*time.Minute)

	if cfg.GoogleClientID == "" && cfg.GitHubClientID == "" {
		return nil, fmt.Errorf("at least one upstream provider must be configured")
	}

	return cfg, nil
}

func (c *Config) PublicBaseURL() string {
	host := strings.TrimSpace(c.PublicHostname)
	if host == "" {
		host = fmt.Sprintf("localhost:%d", c.Port)
	}
	host = strings.TrimRight(host, "/")
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	if isLoopbackHost(host) {
		return "http://" + host
	}
	return "https://" + host
}

func (c *Config) CookiesSecure() bool {
	return strings.HasPrefix(c.PublicBaseURL(), "https://")
}

func detectDriver(dsn string) string {
	switch {
	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		return "postgres"
	case strings.HasPrefix(dsn, "sqlite3://") || strings.HasPrefix(dsn, "sqlite://"):
		return "sqlite"
	case strings.HasSuffix(dsn, ".db") || strings.HasSuffix(dsn, ".sqlite"):
		return "sqlite"
	default:
		return "postgres"
	}
}

func (c *Config) CleanDSN() string {
	dsn := c.DatabaseDSN
	dsn = strings.TrimPrefix(dsn, "postgres://")
	dsn = strings.TrimPrefix(dsn, "postgresql://")
	dsn = strings.TrimPrefix(dsn, "sqlite3://")
	dsn = strings.TrimPrefix(dsn, "sqlite://")
	if c.DatabaseDriver == "postgres" {
		return "postgres://" + dsn
	}
	return dsn
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	switch {
	case strings.HasPrefix(host, "localhost"):
		return true
	case strings.HasPrefix(host, "127.0.0.1"):
		return true
	case strings.HasPrefix(host, "::1"):
		return true
	default:
		return false
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}
