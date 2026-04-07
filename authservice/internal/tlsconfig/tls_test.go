package tlsconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/obot-platform/discobot/authservice/internal/config"
	"github.com/obot-platform/discobot/authservice/internal/database"
	"github.com/obot-platform/discobot/authservice/internal/encryption"
	"github.com/obot-platform/discobot/authservice/internal/store"
)

func TestLoadEphemeralTLS(t *testing.T) {
	cfg := &config.Config{
		HTTPSPort:     3443,
		HTTPSTLSMode:  "ephemeral",
		HTTPSTLSHosts: []string{"localhost", "127.0.0.1"},
	}

	setup, err := Load(cfg, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if setup == nil || setup.TLSConfig == nil {
		t.Fatal("expected TLS setup")
	}
	if setup.Mode != "ephemeral" {
		t.Fatalf("expected mode ephemeral, got %q", setup.Mode)
	}
	if len(setup.TLSConfig.Certificates) != 1 {
		t.Fatal("expected generated certificate")
	}
}

func TestDBCacheRoundTrip(t *testing.T) {
	st := newTestStore(t)
	cache := &dbCache{
		store:     st,
		encryptor: testEncryptor(t),
	}

	plaintext := []byte("sensitive-acme-state")
	if err := cache.Put(context.Background(), "acme/account", plaintext); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := cache.Get(context.Background(), "acme/account")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("Get() = %q, want %q", got, plaintext)
	}

	entry, err := st.GetTLSCacheEntry(context.Background(), "acme/account")
	if err != nil {
		t.Fatalf("GetTLSCacheEntry() error = %v", err)
	}
	if string(entry.EncryptedData) == string(plaintext) {
		t.Fatal("expected encrypted data to differ from plaintext")
	}
}

func TestLoadStaticTLS(t *testing.T) {
	certPath, keyPath := writeStaticCertificate(t)
	cfg := &config.Config{
		HTTPSPort:        3443,
		HTTPSTLSMode:     "static",
		HTTPSTLSCertFile: certPath,
		HTTPSTLSKeyFile:  keyPath,
	}

	setup, err := Load(cfg, nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if setup == nil || len(setup.TLSConfig.Certificates) != 1 {
		t.Fatal("expected static certificate to load")
	}
}

func TestRedirectHTTPToHTTPS(t *testing.T) {
	cfg := &config.Config{HTTPSPort: 3443}
	handler := RedirectHTTPToHTTPS(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "http://localhost:3010/.well-known/openid-configuration?x=1", nil)
	req.Host = "localhost:3010"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusPermanentRedirect {
		t.Fatalf("expected status %d, got %d", http.StatusPermanentRedirect, recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "https://localhost:3443/.well-known/openid-configuration?x=1" {
		t.Fatalf("unexpected redirect location %q", location)
	}
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()

	cfg := &config.Config{
		DatabaseDSN:    "sqlite3://" + t.TempDir() + "/test.db",
		DatabaseDriver: "sqlite",
		EncryptionKey:  []byte("01234567890123456789012345678901"),
	}
	db, err := database.New(cfg)
	if err != nil {
		t.Fatalf("database.New() error = %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	return store.New(db.DB)
}

func testEncryptor(t *testing.T) *encryption.Encryptor {
	t.Helper()
	encryptor, err := encryption.NewEncryptor([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}
	return encryptor
}

func writeStaticCertificate(t *testing.T) (string, string) {
	t.Helper()

	cert, err := generateEphemeralCertificate([]string{"localhost"})
	if err != nil {
		t.Fatalf("generateEphemeralCertificate() error = %v", err)
	}

	dir := t.TempDir()
	certPath := dir + "/server.crt"
	keyPath := dir + "/server.key"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	privateKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected ECDSA private key, got %T", cert.PrivateKey)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	return certPath, keyPath
}
