package config

import "testing"

func TestLoadTLSStaticRequiresCertificateFiles(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "google-client")
	t.Setenv("HTTPS_PORT", "3443")
	t.Setenv("HTTPS_TLS_MODE", "static")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing static TLS files")
	}
}

func TestPublicBaseURLUsesHTTPSPort(t *testing.T) {
	cfg := &Config{Port: 3010, HTTPSPort: 3443}

	if got := cfg.PublicBaseURL(); got != "https://localhost:3443" {
		t.Fatalf("PublicBaseURL() = %q, want %q", got, "https://localhost:3443")
	}
}
