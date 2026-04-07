package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/glebarez/sqlite"
	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/obot-platform/discobot/server/internal/config"
	"github.com/obot-platform/discobot/server/internal/model"
	"github.com/obot-platform/discobot/server/internal/store"
)

func TestAuthService_GetOIDCConfig_DynamicClientRegistration(t *testing.T) {
	t.Parallel()

	var issuer *httptest.Server
	registrationCalls := 0
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 issuer.URL,
				"authorization_endpoint": issuer.URL + "/authorize",
				"token_endpoint":         issuer.URL + "/token",
				"jwks_uri":               issuer.URL + "/jwks",
				"registration_endpoint":  issuer.URL + "/register",
			})
		case "/register":
			registrationCalls++
			var req struct {
				RedirectURIs           []string `json:"redirect_uris"`
				DiscobotInstallationID string   `json:"discobot_installation_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode registration request: %v", err)
			}
			if len(req.RedirectURIs) != 1 || req.RedirectURIs[0] != "https://discobot.example.com/auth/callback" {
				t.Fatalf("unexpected redirect URIs: %#v", req.RedirectURIs)
			}
			if req.DiscobotInstallationID == "" {
				t.Fatal("discobot_installation_id was not sent")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id":                  "dynamic-client-id",
				"client_secret":              "dynamic-client-secret",
				"token_endpoint_auth_method": "client_secret_post",
				"registration_client_uri":    issuer.URL + "/register/dynamic-client-id",
				"registration_access_token":  "registration-access-token",
				"client_id_issued_at":        int64(1712345678),
				"client_secret_expires_at":   int64(1812345678),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()

	authService := newTestAuthService(t, &config.Config{
		EncryptionKey:  []byte("01234567890123456789012345678901"),
		OIDCIssuerURL:  issuer.URL,
		OIDCClientID:   "dynamic",
		PublicHostname: "discobot.example.com",
	})

	oidcConfig, err := authService.getOIDCConfig(context.Background(), "https://discobot.example.com/auth/callback")
	if err != nil {
		t.Fatalf("getOIDCConfig() error = %v", err)
	}

	if oidcConfig.ClientID != "dynamic-client-id" {
		t.Fatalf("ClientID = %q, want dynamic-client-id", oidcConfig.ClientID)
	}
	if oidcConfig.ClientSecret != "dynamic-client-secret" {
		t.Fatalf("ClientSecret = %q, want dynamic-client-secret", oidcConfig.ClientSecret)
	}
	if oidcConfig.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Fatalf("AuthStyle = %v, want %v", oidcConfig.Endpoint.AuthStyle, oauth2.AuthStyleInParams)
	}

	storedRegistration, err := authService.store.GetOIDCClientRegistration(context.Background(), issuer.URL, "https://discobot.example.com")
	if err != nil {
		t.Fatalf("GetOIDCClientRegistration() error = %v", err)
	}
	if got := ptrToString(storedRegistration.TokenEndpointAuthMethod); got != "client_secret_post" {
		t.Fatalf("stored TokenEndpointAuthMethod = %q, want client_secret_post", got)
	}
	if got := ptrToString(storedRegistration.RegistrationClientURI); got != issuer.URL+"/register/dynamic-client-id" {
		t.Fatalf("stored RegistrationClientURI = %q", got)
	}
	if storedRegistration.ClientIDIssuedAt == nil || *storedRegistration.ClientIDIssuedAt != 1712345678 {
		t.Fatalf("stored ClientIDIssuedAt = %v", storedRegistration.ClientIDIssuedAt)
	}
	if storedRegistration.ClientSecretExpiresAt == nil || *storedRegistration.ClientSecretExpiresAt != 1812345678 {
		t.Fatalf("stored ClientSecretExpiresAt = %v", storedRegistration.ClientSecretExpiresAt)
	}
	if len(storedRegistration.RegistrationResponseJSON) == 0 {
		t.Fatal("stored RegistrationResponseJSON is empty")
	}
	registrationAccessToken, err := authService.decryptOIDCClientSecret(storedRegistration.RegistrationAccessToken)
	if err != nil {
		t.Fatalf("decryptOIDCClientSecret(registration access token) error = %v", err)
	}
	if registrationAccessToken != "registration-access-token" {
		t.Fatalf("registration access token = %q, want registration-access-token", registrationAccessToken)
	}
	installation, err := authService.store.GetInstallation(context.Background())
	if err != nil {
		t.Fatalf("GetInstallation() error = %v", err)
	}
	if installation.InstallationID == "" {
		t.Fatal("stored InstallationID is empty")
	}

	oidcConfig, err = authService.getOIDCConfig(context.Background(), "https://discobot.example.com/auth/callback")
	if err != nil {
		t.Fatalf("second getOIDCConfig() error = %v", err)
	}
	if oidcConfig.ClientID != "dynamic-client-id" {
		t.Fatalf("second ClientID = %q, want dynamic-client-id", oidcConfig.ClientID)
	}
	if registrationCalls != 1 {
		t.Fatalf("registrationCalls = %d, want 1", registrationCalls)
	}
}

func TestConfig_PublicBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{
			name: "defaults to localhost port",
			cfg:  &config.Config{Port: 3001},
			want: "http://localhost:3001",
		},
		{
			name: "uses https for public hostname",
			cfg:  &config.Config{PublicHostname: "discobot.example.com", Port: 3001},
			want: "https://discobot.example.com",
		},
		{
			name: "preserves explicit scheme",
			cfg:  &config.Config{PublicHostname: "https://discobot.example.com/app", Port: 3001},
			want: "https://discobot.example.com/app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.cfg.PublicBaseURL(); got != tt.want {
				t.Fatalf("PublicBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func newTestAuthService(t *testing.T, cfg *config.Config) *AuthService {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	if err := db.AutoMigrate(model.AllModels()...); err != nil {
		t.Fatalf("failed to migrate sqlite db: %v", err)
	}

	return NewAuthService(store.New(db, nil), cfg)
}
