package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/obot-platform/discobot/server/internal/config"
	"github.com/obot-platform/discobot/server/internal/encryption"
	"github.com/obot-platform/discobot/server/internal/model"
	"github.com/obot-platform/discobot/server/internal/store"
)

// AuthService handles authentication operations
type AuthService struct {
	store     *store.Store
	cfg       *config.Config
	encryptor *encryption.Encryptor

	oidcMu                   sync.Mutex
	oidcProvider             *oidc.Provider
	oidcRegistrationEndpoint string
}

// User represents an authenticated user (for API responses)
type User struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatarUrl,omitempty"`
	Provider  string `json:"provider"`
}

// NewAuthService creates a new auth service
func NewAuthService(s *store.Store, cfg *config.Config) *AuthService {
	encryptor, err := encryption.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		panic("failed to create auth encryptor: " + err.Error())
	}

	return &AuthService{
		store:     s,
		cfg:       cfg,
		encryptor: encryptor,
	}
}

// GetOIDCAuthURL returns the OIDC authorization URL for the configured provider.
func (s *AuthService) GetOIDCAuthURL(ctx context.Context, redirectURL, state, nonce, codeChallenge string) (string, error) {
	config, err := s.getOIDCConfig(ctx, redirectURL)
	if err != nil {
		return "", err
	}

	return config.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

// ExchangeOIDCCode exchanges an authorization code for an OIDC identity.
func (s *AuthService) ExchangeOIDCCode(ctx context.Context, redirectURL, code, nonce, verifier string) (*User, error) {
	config, err := s.getOIDCConfig(ctx, redirectURL)
	if err != nil {
		return nil, err
	}

	token, err := config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("provider did not return an id_token")
	}

	provider, _, err := s.getOIDCProvider(ctx)
	if err != nil {
		return nil, err
	}
	verifierRef := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	idToken, err := verifierRef.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id_token: %w", err)
	}

	var claims struct {
		Subject       string `json:"sub"`
		Issuer        string `json:"iss"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Nonce         string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %w", err)
	}

	if claims.Nonce == "" || claims.Nonce != nonce {
		return nil, fmt.Errorf("invalid OIDC nonce")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("OIDC token missing subject")
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("OIDC token missing email")
	}
	if !claims.EmailVerified {
		return nil, fmt.Errorf("OIDC email is not verified")
	}

	issuer := strings.TrimSpace(claims.Issuer)
	if issuer == "" {
		issuer = strings.TrimSpace(s.cfg.OIDCIssuerURL)
	}

	return &User{
		ID:        issuer + "|" + claims.Subject,
		Email:     claims.Email,
		Name:      claims.Name,
		AvatarURL: claims.Picture,
		Provider:  "oidc",
	}, nil
}

// CreateOrUpdateUser creates or updates a user in the database
func (s *AuthService) CreateOrUpdateUser(ctx context.Context, user *User) (*User, error) {
	// Check if user exists
	existing, err := s.store.GetUserByProviderID(ctx, user.Provider, user.ID)
	if err == nil {
		// Update existing user
		existing.Name = strPtr(user.Name)
		existing.AvatarURL = strPtr(user.AvatarURL)
		if err := s.store.UpdateUser(ctx, existing); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
		result := &User{
			ID:        existing.ID,
			Email:     existing.Email,
			Name:      ptrToString(existing.Name),
			AvatarURL: ptrToString(existing.AvatarURL),
			Provider:  existing.Provider,
		}
		if err := s.ensureDefaultProjectBootstrap(ctx, existing.ID); err != nil {
			return nil, err
		}
		return result, nil
	}

	existing, err = s.store.GetUserByEmail(ctx, user.Email)
	if err == nil {
		existing.Provider = user.Provider
		existing.ProviderID = user.ID
		existing.Name = strPtr(user.Name)
		existing.AvatarURL = strPtr(user.AvatarURL)
		if err := s.store.UpdateUser(ctx, existing); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
		result := &User{
			ID:        existing.ID,
			Email:     existing.Email,
			Name:      ptrToString(existing.Name),
			AvatarURL: ptrToString(existing.AvatarURL),
			Provider:  existing.Provider,
		}
		if err := s.ensureDefaultProjectBootstrap(ctx, existing.ID); err != nil {
			return nil, err
		}
		return result, nil
	}

	// Create new user
	newUser := &model.User{
		Email:      user.Email,
		Name:       strPtr(user.Name),
		AvatarURL:  strPtr(user.AvatarURL),
		Provider:   user.Provider,
		ProviderID: user.ID,
	}
	if err := s.store.CreateUser(ctx, newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	if err := s.ensureDefaultProjectBootstrap(ctx, newUser.ID); err != nil {
		return nil, err
	}

	return &User{
		ID:        newUser.ID,
		Email:     newUser.Email,
		Name:      ptrToString(newUser.Name),
		AvatarURL: ptrToString(newUser.AvatarURL),
		Provider:  newUser.Provider,
	}, nil
}

func (s *AuthService) ensureDefaultProjectBootstrap(ctx context.Context, userID string) error {
	if _, err := s.store.GetProjectMember(ctx, model.DefaultProjectID, userID); err == nil {
		return nil
	} else if err != store.ErrNotFound {
		return fmt.Errorf("failed to check default project membership: %w", err)
	}

	members, err := s.store.ListProjectMembers(ctx, model.DefaultProjectID)
	if err != nil {
		return fmt.Errorf("failed to inspect default project members: %w", err)
	}

	for _, member := range members {
		if member.UserID != model.AnonymousUserID {
			return nil
		}
	}

	now := time.Now()
	member := &model.ProjectMember{
		ProjectID:  model.DefaultProjectID,
		UserID:     userID,
		Role:       "owner",
		InvitedBy:  &userID,
		InvitedAt:  &now,
		AcceptedAt: &now,
	}
	if err := s.store.CreateProjectMember(ctx, member); err != nil {
		return fmt.Errorf("failed to bootstrap default project owner: %w", err)
	}
	return nil
}

// CreateSession creates a new session for a user and returns the token
func (s *AuthService) CreateSession(ctx context.Context, userID string) (string, error) {
	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash token for storage
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	// Set expiry (30 days)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	session := &model.UserSession{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}
	if err := s.store.CreateUserSession(ctx, session); err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	return token, nil
}

// ValidateSession validates a session token and returns the user
func (s *AuthService) ValidateSession(ctx context.Context, token string) (*User, error) {
	// Hash token
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	session, err := s.store.GetUserSessionByToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %w", err)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session expired")
	}

	// Get user - if preloaded, use that; otherwise fetch
	var user *model.User
	if session.User != nil {
		user = session.User
	} else {
		user, err = s.store.GetUserByID(ctx, session.UserID)
		if err != nil {
			return nil, fmt.Errorf("user not found: %w", err)
		}
	}

	return &User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      ptrToString(user.Name),
		AvatarURL: ptrToString(user.AvatarURL),
		Provider:  user.Provider,
	}, nil
}

// DeleteSession deletes a session by token
func (s *AuthService) DeleteSession(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])
	return s.store.DeleteUserSession(ctx, tokenHash)
}

// GetUserByID retrieves a user by ID
func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*User, error) {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      ptrToString(user.Name),
		AvatarURL: ptrToString(user.AvatarURL),
		Provider:  user.Provider,
	}, nil
}

func (s *AuthService) getOIDCConfig(ctx context.Context, redirectURL string) (*oauth2.Config, error) {
	if s.cfg.OIDCIssuerURL == "" || s.cfg.OIDCClientID == "" {
		return nil, fmt.Errorf("OIDC is not configured")
	}

	provider, _, err := s.getOIDCProvider(ctx)
	if err != nil {
		return nil, err
	}

	clientID := s.cfg.OIDCClientID
	clientSecret := s.cfg.OIDCClientSecret
	endpointAuthMethod := ""
	if clientID == "dynamic" {
		registration, regErr := s.getOrCreateOIDCClientRegistration(ctx)
		if regErr != nil {
			return nil, regErr
		}
		clientID = registration.ClientID
		clientSecret = registration.ClientSecret
		endpointAuthMethod = registration.TokenEndpointAuthMethod
	}

	scopes := s.cfg.OIDCScopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   provider.Endpoint().AuthURL,
			TokenURL:  provider.Endpoint().TokenURL,
			AuthStyle: authStyleFromTokenEndpointAuthMethod(endpointAuthMethod),
		},
		Scopes:      scopes,
		RedirectURL: redirectURL,
	}, nil
}

func (s *AuthService) getOIDCProvider(ctx context.Context) (*oidc.Provider, string, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()

	if s.oidcProvider == nil {
		discoveryURL := s.cfg.OIDCBackchannelURL() + "/.well-known/openid-configuration"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create OIDC discovery request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("failed to initialize OIDC provider: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)
			return nil, "", fmt.Errorf("failed to initialize OIDC provider: %s: %s", resp.Status, string(body))
		}

		var metadata struct {
			Issuer               string   `json:"issuer"`
			AuthURL              string   `json:"authorization_endpoint"`
			TokenURL             string   `json:"token_endpoint"`
			UserInfoURL          string   `json:"userinfo_endpoint"`
			JWKSURL              string   `json:"jwks_uri"`
			RegistrationEndpoint string   `json:"registration_endpoint"`
			Algorithms           []string `json:"id_token_signing_alg_values_supported"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
			return nil, "", fmt.Errorf("failed to decode OIDC discovery metadata: %w", err)
		}
		if strings.TrimSpace(metadata.Issuer) != strings.TrimSpace(s.cfg.OIDCIssuerURL) {
			return nil, "", fmt.Errorf("OIDC discovery issuer mismatch: got %q want %q", metadata.Issuer, s.cfg.OIDCIssuerURL)
		}

		provider := (&oidc.ProviderConfig{
			IssuerURL: metadata.Issuer,
			AuthURL:   metadata.AuthURL,
			TokenURL:  rewriteToBackchannel(metadata.TokenURL, s.cfg.OIDCBackchannelURL()),
			UserInfoURL: rewriteToBackchannel(
				metadata.UserInfoURL,
				s.cfg.OIDCBackchannelURL(),
			),
			JWKSURL:    rewriteToBackchannel(metadata.JWKSURL, s.cfg.OIDCBackchannelURL()),
			Algorithms: metadata.Algorithms,
		}).NewProvider(ctx)

		s.oidcProvider = provider
		s.oidcRegistrationEndpoint = rewriteToBackchannel(
			strings.TrimSpace(metadata.RegistrationEndpoint),
			s.cfg.OIDCBackchannelURL(),
		)
	}

	return s.oidcProvider, s.oidcRegistrationEndpoint, nil
}

type oidcClientRegistration struct {
	ClientID                string
	ClientSecret            string
	TokenEndpointAuthMethod string
}

func (s *AuthService) getOrCreateInstallationID(ctx context.Context) (string, error) {
	installation, err := s.store.GetInstallation(ctx)
	if err == nil {
		return installation.InstallationID, nil
	}
	if err != store.ErrNotFound {
		return "", fmt.Errorf("failed to load installation: %w", err)
	}

	installationID := uuid.New().String()
	installation = &model.Installation{
		InstallationID: installationID,
	}
	if err := s.store.CreateInstallation(ctx, installation); err != nil {
		return "", fmt.Errorf("failed to create installation: %w", err)
	}
	return installationID, nil
}

func (s *AuthService) getOrCreateOIDCClientRegistration(ctx context.Context) (*oidcClientRegistration, error) {
	redirectBaseURL := s.cfg.PublicBaseURL()
	if registration, err := s.store.GetOIDCClientRegistration(ctx, s.cfg.OIDCIssuerURL, redirectBaseURL); err == nil {
		clientSecret, decErr := s.decryptOIDCClientSecret(registration.ClientSecretEncryptedData)
		if decErr != nil {
			return nil, decErr
		}
		return &oidcClientRegistration{
			ClientID:                registration.ClientID,
			ClientSecret:            clientSecret,
			TokenEndpointAuthMethod: ptrToString(registration.TokenEndpointAuthMethod),
		}, nil
	} else if err != store.ErrNotFound {
		return nil, fmt.Errorf("failed to load OIDC client registration: %w", err)
	}

	_, registrationEndpoint, err := s.getOIDCProvider(ctx)
	if err != nil {
		return nil, err
	}
	if registrationEndpoint == "" {
		return nil, fmt.Errorf("OIDC provider does not support dynamic client registration")
	}

	redirectURI := redirectBaseURL + "/auth/callback"
	installationID, err := s.getOrCreateInstallationID(ctx)
	if err != nil {
		return nil, err
	}
	reqBody := map[string]any{
		"client_name":                "Discobot",
		"discobot_installation_id":   installationID,
		"application_type":           "web",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "client_secret_basic",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode dynamic client registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register OIDC client: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return nil, fmt.Errorf("OIDC client registration failed: %s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("OIDC client registration failed with status %d", resp.StatusCode)
	}

	var registrationResp struct {
		ClientID                string `json:"client_id"`
		ClientSecret            string `json:"client_secret"`
		TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
		RegistrationClientURI   string `json:"registration_client_uri"`
		RegistrationAccessToken string `json:"registration_access_token"`
		ClientIDIssuedAt        *int64 `json:"client_id_issued_at"`
		ClientSecretExpiresAt   *int64 `json:"client_secret_expires_at"`
	}
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read dynamic client registration response: %w", err)
	}
	if err := json.Unmarshal(responseBody, &registrationResp); err != nil {
		return nil, fmt.Errorf("failed to decode dynamic client registration response: %w", err)
	}
	if registrationResp.ClientID == "" {
		return nil, fmt.Errorf("dynamic client registration response missing client_id")
	}

	encryptedSecret, err := s.encryptOIDCClientSecret(registrationResp.ClientSecret)
	if err != nil {
		return nil, err
	}

	registrationAccessTokenEncrypted, err := s.encryptOIDCClientSecret(registrationResp.RegistrationAccessToken)
	if err != nil {
		return nil, err
	}

	modelRegistration := &model.OIDCClientRegistration{
		IssuerURL:                 s.cfg.OIDCIssuerURL,
		RedirectBaseURL:           redirectBaseURL,
		ClientID:                  registrationResp.ClientID,
		ClientSecretEncryptedData: encryptedSecret,
		TokenEndpointAuthMethod:   strPtr(registrationResp.TokenEndpointAuthMethod),
		RegistrationClientURI:     strPtr(registrationResp.RegistrationClientURI),
		RegistrationAccessToken:   registrationAccessTokenEncrypted,
		ClientIDIssuedAt:          registrationResp.ClientIDIssuedAt,
		ClientSecretExpiresAt:     registrationResp.ClientSecretExpiresAt,
		RegistrationResponseJSON:  responseBody,
	}
	if err := s.store.CreateOIDCClientRegistration(ctx, modelRegistration); err != nil {
		return nil, fmt.Errorf("failed to persist OIDC client registration: %w", err)
	}

	return &oidcClientRegistration{
		ClientID:                registrationResp.ClientID,
		ClientSecret:            registrationResp.ClientSecret,
		TokenEndpointAuthMethod: registrationResp.TokenEndpointAuthMethod,
	}, nil
}

func (s *AuthService) encryptOIDCClientSecret(secret string) ([]byte, error) {
	if secret == "" {
		return nil, nil
	}
	encrypted, err := s.encryptor.Encrypt([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt OIDC client secret: %w", err)
	}
	return encrypted, nil
}

func (s *AuthService) decryptOIDCClientSecret(encrypted []byte) (string, error) {
	if len(encrypted) == 0 {
		return "", nil
	}
	decrypted, err := s.encryptor.Decrypt(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt OIDC client secret: %w", err)
	}
	return string(decrypted), nil
}

func authStyleFromTokenEndpointAuthMethod(method string) oauth2.AuthStyle {
	switch strings.TrimSpace(method) {
	case "client_secret_post":
		return oauth2.AuthStyleInParams
	case "client_secret_basic":
		return oauth2.AuthStyleInHeader
	default:
		return oauth2.AuthStyleAutoDetect
	}
}

func rewriteToBackchannel(rawURL, backchannelBaseURL string) string {
	if strings.TrimSpace(rawURL) == "" || strings.TrimSpace(backchannelBaseURL) == "" {
		return strings.TrimSpace(rawURL)
	}

	original, err := url.Parse(rawURL)
	if err != nil {
		return strings.TrimSpace(rawURL)
	}
	backchannel, err := url.Parse(backchannelBaseURL)
	if err != nil {
		return strings.TrimSpace(rawURL)
	}

	original.Scheme = backchannel.Scheme
	original.Host = backchannel.Host
	return original.String()
}

// GenerateState generates a random state for OAuth
func GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Helper functions for null handling
func ptrToString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
