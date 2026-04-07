package config

import (
	"encoding/hex"
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
	HTTPSPort            int
	HTTPSTLSMode         string
	HTTPSTLSCertFile     string
	HTTPSTLSKeyFile      string
	HTTPSTLSHosts        []string
	HTTPSACMEEmail       string
	DatabaseDSN          string
	DatabaseDriver       string
	EncryptionKey        []byte
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
	cfg.HTTPSPort = getEnvInt("HTTPS_PORT", 0)
	cfg.HTTPSTLSMode = strings.ToLower(getEnv("HTTPS_TLS_MODE", "ephemeral"))
	cfg.HTTPSTLSCertFile = getEnv("HTTPS_TLS_CERT_FILE", "")
	cfg.HTTPSTLSKeyFile = getEnv("HTTPS_TLS_KEY_FILE", "")
	cfg.HTTPSTLSHosts = compactStrings(getEnvList("HTTPS_TLS_HOSTS", []string{"localhost"}))
	cfg.HTTPSACMEEmail = getEnv("HTTPS_ACME_EMAIL", "")
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

	if cfg.HTTPSPort == cfg.Port && cfg.HTTPSPort > 0 {
		return nil, fmt.Errorf("HTTPS_PORT must be different from PORT")
	}
	switch cfg.HTTPSTLSMode {
	case "", "ephemeral":
		cfg.HTTPSTLSMode = "ephemeral"
	case "static":
		if cfg.HTTPSPort > 0 && (cfg.HTTPSTLSCertFile == "" || cfg.HTTPSTLSKeyFile == "") {
			return nil, fmt.Errorf("HTTPS_TLS_CERT_FILE and HTTPS_TLS_KEY_FILE are required when HTTPS_TLS_MODE=static")
		}
	case "acme":
		if cfg.HTTPSPort > 0 && len(cfg.HTTPSTLSHosts) == 0 {
			return nil, fmt.Errorf("HTTPS_TLS_HOSTS is required when HTTPS_TLS_MODE=acme")
		}
	default:
		return nil, fmt.Errorf("HTTPS_TLS_MODE must be one of: ephemeral, static, acme")
	}

	encryptionKeyStr := getEnv("ENCRYPTION_KEY", "")
	if encryptionKeyStr == "" {
		encryptionKeyStr = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}
	encryptionKey, err := hex.DecodeString(encryptionKeyStr)
	if err != nil {
		return nil, fmt.Errorf("ENCRYPTION_KEY must be hex encoded: %w", err)
	}
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars), got %d bytes", len(encryptionKey))
	}
	cfg.EncryptionKey = encryptionKey

	if cfg.GoogleClientID == "" && cfg.GitHubClientID == "" {
		return nil, fmt.Errorf("at least one upstream provider must be configured")
	}

	return cfg, nil
}

func (c *Config) PublicBaseURL() string {
	host := strings.TrimSpace(c.PublicHostname)
	if host == "" {
		port := c.Port
		if c.HTTPSPort > 0 {
			port = c.HTTPSPort
		}
		host = fmt.Sprintf("localhost:%d", port)
	}
	host = strings.TrimRight(host, "/")
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	if c.HTTPSPort > 0 {
		return "https://" + host
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

func getEnvList(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}
