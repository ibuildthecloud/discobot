package service

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/obot-platform/discobot/authservice/internal/config"
	"github.com/obot-platform/discobot/authservice/internal/model"
	"github.com/obot-platform/discobot/authservice/internal/store"
)

func TestRegisterClientRoundTrip(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)

	resp, err := svc.RegisterClient(context.Background(), ClientRegistrationRequest{
		RedirectURIs:            []string{"https://discobot.example.com/auth/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ClientName:              "Discobot",
		DiscobotInstallationID:  "installation-123",
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	if resp.ClientID == "" || resp.ClientSecret == "" || resp.RegistrationAccessToken == "" {
		t.Fatal("expected client credentials and registration token")
	}

	stored, err := svc.GetClientRegistration(context.Background(), resp.ClientID, resp.RegistrationAccessToken)
	if err != nil {
		t.Fatalf("GetClientRegistration() error = %v", err)
	}
	if stored.ClientID != resp.ClientID {
		t.Fatalf("ClientID = %q, want %q", stored.ClientID, resp.ClientID)
	}
	if stored.DiscobotInstallationID != "installation-123" {
		t.Fatalf("DiscobotInstallationID = %q", stored.DiscobotInstallationID)
	}
}

func TestMetadataIncludesRequiredEndpoints(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)

	metadata := svc.Metadata()
	if metadata["issuer"] != "https://auth.example.com" {
		t.Fatalf("issuer = %v", metadata["issuer"])
	}
	if metadata["registration_endpoint"] != "https://auth.example.com/register" {
		t.Fatalf("registration_endpoint = %v", metadata["registration_endpoint"])
	}
	if metadata["jwks_uri"] != "https://auth.example.com/.well-known/jwks.json" {
		t.Fatalf("jwks_uri = %v", metadata["jwks_uri"])
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	if err := db.AutoMigrate(model.AllModels()...); err != nil {
		t.Fatalf("failed to migrate sqlite db: %v", err)
	}
	cfg := &config.Config{
		Port:                 3010,
		PublicHostname:       "auth.example.com",
		BrowserSessionTTL:    24 * time.Hour,
		AuthorizationCodeTTL: 5 * time.Minute,
		AccessTokenTTL:       15 * time.Minute,
	}
	return New(store.New(db, nil), cfg)
}
