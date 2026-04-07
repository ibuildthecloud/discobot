package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	jwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/obot-platform/discobot/authservice/internal/config"
	"github.com/obot-platform/discobot/authservice/internal/encryption"
	"github.com/obot-platform/discobot/authservice/internal/model"
	"github.com/obot-platform/discobot/authservice/internal/store"
)

type Service struct {
	store     *store.Store
	cfg       *config.Config
	encryptor *encryption.Encryptor
}

type UpstreamIdentity struct {
	Provider       string
	ProviderUserID string
	Email          string
	Username       string
	Name           string
	EmailVerified  bool
}

type ClientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	SoftwareID              string   `json:"software_id"`
	SoftwareVersion         string   `json:"software_version"`
	DiscobotInstallationID  string   `json:"discobot_installation_id"`
}

type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	DiscobotInstallationID  string   `json:"discobot_installation_id,omitempty"`
}

type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type ProviderLink struct {
	Name string
	URL  string
}

type LoginPageData struct {
	Title        string
	Subtitle     string
	Providers    []ProviderLink
	ReturnTo     string
	HasProviders bool
}

func New(st *store.Store, cfg *config.Config) (*Service, error) {
	encryptor, err := encryption.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create authservice encryptor: %w", err)
	}
	return &Service{store: st, cfg: cfg, encryptor: encryptor}, nil
}

func GenerateState() (string, error) {
	return randomToken(16)
}

func (s *Service) ProviderAvailable(provider string) bool {
	switch provider {
	case "google":
		return s.cfg.GoogleClientID != "" && s.cfg.GoogleClientSecret != ""
	case "github":
		return s.cfg.GitHubClientID != "" && s.cfg.GitHubClientSecret != ""
	default:
		return false
	}
}

func (s *Service) EnabledProviders() []string {
	providers := make([]string, 0, 2)
	if s.ProviderAvailable("google") {
		providers = append(providers, "google")
	}
	if s.ProviderAvailable("github") {
		providers = append(providers, "github")
	}
	return providers
}

func (s *Service) SingleProvider() (string, bool) {
	providers := s.EnabledProviders()
	if len(providers) == 1 {
		return providers[0], true
	}
	return "", false
}

func (s *Service) LoginPageData(returnTo string) LoginPageData {
	providers := make([]ProviderLink, 0, 2)
	for _, provider := range s.EnabledProviders() {
		switch provider {
		case "google":
			providers = append(providers, ProviderLink{Name: "Google", URL: "/login/google?return_to=" + url.QueryEscape(returnTo)})
		case "github":
			providers = append(providers, ProviderLink{Name: "GitHub", URL: "/login/github?return_to=" + url.QueryEscape(returnTo)})
		}
	}
	return LoginPageData{
		Title:        "Sign in to Discobot",
		Subtitle:     "Choose an identity provider to continue.",
		Providers:    providers,
		ReturnTo:     returnTo,
		HasProviders: len(providers) > 0,
	}
}

func (s *Service) AuthorizationURL(provider, state, redirectURL string) (string, error) {
	switch provider {
	case "google":
		cfg := &oauth2.Config{ClientID: s.cfg.GoogleClientID, ClientSecret: s.cfg.GoogleClientSecret, RedirectURL: redirectURL, Scopes: []string{"openid", "email", "profile"}, Endpoint: google.Endpoint}
		return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
	case "github":
		cfg := &oauth2.Config{ClientID: s.cfg.GitHubClientID, ClientSecret: s.cfg.GitHubClientSecret, RedirectURL: redirectURL, Scopes: []string{"read:user", "user:email"}, Endpoint: github.Endpoint}
		return cfg.AuthCodeURL(state), nil
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (s *Service) ExchangeUpstreamIdentity(ctx context.Context, provider, code, redirectURL string) (*UpstreamIdentity, error) {
	switch provider {
	case "google":
		return s.exchangeGoogle(ctx, code, redirectURL)
	case "github":
		return s.exchangeGitHub(ctx, code, redirectURL)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (s *Service) exchangeGoogle(ctx context.Context, code, redirectURL string) (*UpstreamIdentity, error) {
	cfg := &oauth2.Config{ClientID: s.cfg.GoogleClientID, ClientSecret: s.cfg.GoogleClientSecret, RedirectURL: redirectURL, Scopes: []string{"openid", "email", "profile"}, Endpoint: google.Endpoint}
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	client := cfg.Client(ctx, token)
	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var user struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &UpstreamIdentity{Provider: "google", ProviderUserID: user.Subject, Email: user.Email, Username: usernameFromEmail(user.Email), Name: user.Name, EmailVerified: user.EmailVerified}, nil
}

func (s *Service) exchangeGitHub(ctx context.Context, code, redirectURL string) (*UpstreamIdentity, error) {
	cfg := &oauth2.Config{ClientID: s.cfg.GitHubClientID, ClientSecret: s.cfg.GitHubClientSecret, RedirectURL: redirectURL, Scopes: []string{"read:user", "user:email"}, Endpoint: github.Endpoint}
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	client := cfg.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	email := user.Email
	verified := false
	if email == "" {
		email, verified, err = s.githubVerifiedEmail(ctx, client)
		if err != nil {
			return nil, err
		}
	}
	if !verified {
		return nil, fmt.Errorf("github did not provide a verified email")
	}
	return &UpstreamIdentity{Provider: "github", ProviderUserID: fmt.Sprintf("%d", user.ID), Email: email, Username: user.Login, Name: user.Name, EmailVerified: true}, nil
}

func (s *Service) githubVerifiedEmail(ctx context.Context, client *http.Client) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, err
	}
	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, true, nil
		}
	}
	for _, email := range emails {
		if email.Verified {
			return email.Email, true, nil
		}
	}
	return "", false, nil
}

func (s *Service) CreateOrUpdateUser(ctx context.Context, identity *UpstreamIdentity) (*model.User, error) {
	if !identity.EmailVerified {
		return nil, fmt.Errorf("email is not verified")
	}
	if existingIdentity, err := s.store.GetIdentity(ctx, identity.Provider, identity.ProviderUserID); err == nil {
		user, err := s.store.GetUserByEmail(ctx, identity.Email)
		if err == nil {
			user.Username = identity.Username
			if err := s.store.UpdateUser(ctx, user); err != nil {
				return nil, err
			}
		}
		existingIdentity.Email = identity.Email
		existingIdentity.Username = identity.Username
		if err := s.store.UpdateIdentity(ctx, existingIdentity); err != nil {
			return nil, err
		}
		return user, nil
	} else if err != store.ErrNotFound {
		return nil, err
	}

	user, err := s.store.GetUserByEmail(ctx, identity.Email)
	if err == store.ErrNotFound {
		user = &model.User{Email: identity.Email, Username: identity.Username}
		if err := s.store.CreateUser(ctx, user); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		user.Username = identity.Username
		if err := s.store.UpdateUser(ctx, user); err != nil {
			return nil, err
		}
	}

	link := &model.Identity{UserID: user.ID, Provider: identity.Provider, ProviderUserID: identity.ProviderUserID, Email: identity.Email, Username: identity.Username}
	if err := s.store.CreateIdentity(ctx, link); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) CreateBrowserSession(ctx context.Context, userID string) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	session := &model.BrowserSession{UserID: userID, TokenHash: store.HashString(token), ExpiresAt: time.Now().Add(s.cfg.BrowserSessionTTL)}
	if err := s.store.CreateBrowserSession(ctx, session); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) GetUserBySessionToken(ctx context.Context, token string) (*model.User, error) {
	session, err := s.store.GetBrowserSessionByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if store.Expired(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}
	return s.store.GetUserByID(ctx, session.UserID)
}

func (s *Service) LogoutBrowserSession(ctx context.Context, token string) error {
	return s.store.DeleteBrowserSession(ctx, token)
}

func (s *Service) RegisterClient(ctx context.Context, req ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	if len(req.RedirectURIs) == 0 {
		return nil, fmt.Errorf("redirect_uris is required")
	}
	if req.ClientName == "" {
		req.ClientName = "Discobot"
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	clientID := uuid.New().String()
	clientSecret, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	registrationAccessToken, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	redirectURIsJSON, err := store.EncodeStringSlice(req.RedirectURIs)
	if err != nil {
		return nil, err
	}
	grantTypesJSON, err := store.EncodeStringSlice(req.GrantTypes)
	if err != nil {
		return nil, err
	}
	responseTypesJSON, err := store.EncodeStringSlice(req.ResponseTypes)
	if err != nil {
		return nil, err
	}
	rawMetadataJSON, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	issuedAt := time.Now().Unix()
	client := &model.OAuthClient{
		ClientID:                    clientID,
		ClientSecretHash:            store.HashString(clientSecret),
		ClientName:                  req.ClientName,
		ClientURI:                   strPtr(req.ClientURI),
		SoftwareID:                  strPtr(req.SoftwareID),
		SoftwareVersion:             strPtr(req.SoftwareVersion),
		DiscobotInstallationID:      strPtr(req.DiscobotInstallationID),
		RedirectURIsJSON:            redirectURIsJSON,
		GrantTypesJSON:              grantTypesJSON,
		ResponseTypesJSON:           responseTypesJSON,
		TokenEndpointAuthMethod:     req.TokenEndpointAuthMethod,
		RegistrationAccessTokenHash: store.HashString(registrationAccessToken),
		ClientIDIssuedAt:            issuedAt,
		ClientSecretExpiresAt:       0,
		RawMetadataJSON:             rawMetadataJSON,
	}
	if err := s.store.CreateOAuthClient(ctx, client); err != nil {
		return nil, err
	}
	return &ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        issuedAt,
		ClientSecretExpiresAt:   0,
		RegistrationClientURI:   s.cfg.PublicBaseURL() + "/register/" + clientID,
		RegistrationAccessToken: registrationAccessToken,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
		DiscobotInstallationID:  req.DiscobotInstallationID,
	}, nil
}

func (s *Service) GetClientRegistration(ctx context.Context, clientID, registrationAccessToken string) (*ClientRegistrationResponse, error) {
	client, err := s.store.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client.RegistrationAccessTokenHash != store.HashString(registrationAccessToken) {
		return nil, fmt.Errorf("invalid registration access token")
	}
	return s.clientRegistrationResponse(client, "")
}

func (s *Service) GetAuthorizeClient(ctx context.Context, req AuthorizeRequest) (*model.OAuthClient, error) {
	client, err := s.store.GetOAuthClientByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	redirects, err := store.DecodeStringSlice(client.RedirectURIsJSON)
	if err != nil {
		return nil, err
	}
	if !contains(redirects, req.RedirectURI) {
		return nil, fmt.Errorf("invalid redirect_uri")
	}
	if req.ResponseType != "code" {
		return nil, fmt.Errorf("unsupported response_type")
	}
	if !strings.Contains(req.Scope, "openid") {
		return nil, fmt.Errorf("scope must include openid")
	}
	return client, nil
}

func (s *Service) CreateAuthorizationCode(ctx context.Context, client *model.OAuthClient, user *model.User, req AuthorizeRequest) (string, error) {
	rawCode, err := randomToken(32)
	if err != nil {
		return "", err
	}
	code := &model.AuthorizationCode{CodeHash: store.HashString(rawCode), ClientID: client.ClientID, UserID: user.ID, RedirectURI: req.RedirectURI, Scope: req.Scope, Nonce: strPtr(req.Nonce), CodeChallenge: strPtr(req.CodeChallenge), CodeChallengeMethod: strPtr(req.CodeChallengeMethod), ExpiresAt: time.Now().Add(s.cfg.AuthorizationCodeTTL)}
	if err := s.store.CreateAuthorizationCode(ctx, code); err != nil {
		return "", err
	}
	return rawCode, nil
}

func (s *Service) ExchangeAuthorizationCode(ctx context.Context, clientID, clientSecret, code, redirectURI, codeVerifier string) (map[string]any, error) {
	client, err := s.store.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client.ClientSecretHash != store.HashString(clientSecret) {
		return nil, fmt.Errorf("invalid client secret")
	}
	authCode, err := s.store.GetAuthorizationCodeByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	if authCode.ClientID != client.ClientID || authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("invalid authorization code")
	}
	if authCode.UsedAt != nil || time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}
	if err := validatePKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
		return nil, err
	}
	user, err := s.store.GetUserByID(ctx, authCode.UserID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	usedAt := now
	authCode.UsedAt = &usedAt
	if err := s.store.UpdateAuthorizationCode(ctx, authCode); err != nil {
		return nil, err
	}
	idToken, accessToken, err := s.issueTokens(client, user, authCode, now)
	if err != nil {
		return nil, err
	}
	return map[string]any{"access_token": accessToken, "id_token": idToken, "token_type": "Bearer", "expires_in": int(s.cfg.AccessTokenTTL.Seconds()), "scope": authCode.Scope}, nil
}

func (s *Service) UserInfoFromToken(ctx context.Context, accessToken string) (map[string]any, error) {
	claims, err := s.parseSignedToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	return map[string]any{"sub": claims.Subject, "email": claims.Email, "email_verified": true, "preferred_username": claims.PreferredUsername, "username": claims.Username}, nil
}

func (s *Service) Metadata() map[string]any {
	base := s.cfg.PublicBaseURL()
	return map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"userinfo_endpoint":                     base + "/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"registration_endpoint":                 base + "/register",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "preferred_username", "username"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
}

func (s *Service) JWKS(ctx context.Context) (map[string]any, error) {
	priv, kid, err := s.signingKey(ctx)
	if err != nil {
		return nil, err
	}
	jwk := jose.JSONWebKey{Key: priv.Public(), KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}
	return map[string]any{"keys": []jose.JSONWebKey{jwk.Public()}}, nil
}

type tokenClaims struct {
	Email             string `json:"email"`
	Username          string `json:"username"`
	PreferredUsername string `json:"preferred_username"`
	EmailVerified     bool   `json:"email_verified"`
	Nonce             string `json:"nonce,omitempty"`
	Scope             string `json:"scope,omitempty"`
	TokenUse          string `json:"token_use,omitempty"`
}

func (s *Service) issueTokens(client *model.OAuthClient, user *model.User, code *model.AuthorizationCode, now time.Time) (string, string, error) {
	priv, kid, err := s.signingKey(context.Background())
	if err != nil {
		return "", "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}}, nil)
	if err != nil {
		return "", "", err
	}
	baseClaims := jwt.Claims{Issuer: s.cfg.PublicBaseURL(), Subject: user.ID, Audience: jwt.Audience{client.ClientID}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenTTL))}
	idClaims := tokenClaims{Email: user.Email, Username: user.Username, PreferredUsername: user.Username, EmailVerified: true, Nonce: ptrToString(code.Nonce)}
	idToken, err := jwt.Signed(signer).Claims(baseClaims).Claims(idClaims).Serialize()
	if err != nil {
		return "", "", err
	}
	accessClaims := tokenClaims{Email: user.Email, Username: user.Username, PreferredUsername: user.Username, EmailVerified: true, Scope: code.Scope, TokenUse: "access_token"}
	accessToken, err := jwt.Signed(signer).Claims(baseClaims).Claims(accessClaims).Serialize()
	if err != nil {
		return "", "", err
	}
	return idToken, accessToken, nil
}

func (s *Service) parseSignedToken(ctx context.Context, token string) (*struct {
	jwt.Claims
	tokenClaims
}, error) {
	priv, _, err := s.signingKey(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, err
	}
	claims := &struct {
		jwt.Claims
		tokenClaims
	}{}
	if err := parsed.Claims(priv.Public(), claims); err != nil {
		return nil, err
	}
	if err := claims.Validate(jwt.Expected{Issuer: s.cfg.PublicBaseURL(), Time: time.Now()}); err != nil {
		return nil, err
	}
	return claims, nil
}

func (s *Service) signingKey(ctx context.Context) (ed25519.PrivateKey, string, error) {
	stored, err := s.store.GetActiveSigningKey(ctx)
	if err == nil {
		decrypted, err := s.encryptor.Decrypt(stored.PrivateKeyEncryptedData)
		if err != nil {
			return nil, "", fmt.Errorf("decrypt signing key: %w", err)
		}
		priv, err := parsePrivateKeyPEM(string(decrypted))
		return priv, stored.Kid, err
	}
	if err != store.ErrNotFound {
		return nil, "", err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", err
	}
	kid := uuid.New().String()
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	encrypted, err := s.encryptor.Encrypt([]byte(privateKeyPEM))
	if err != nil {
		return nil, "", fmt.Errorf("encrypt signing key: %w", err)
	}
	key := &model.SigningKey{Kid: kid, Algorithm: "EdDSA", PrivateKeyEncryptedData: encrypted, Active: true}
	if err := s.store.CreateSigningKey(ctx, key); err != nil {
		return nil, "", err
	}
	return priv, kid, nil
}

func (s *Service) clientRegistrationResponse(client *model.OAuthClient, clientSecret string) (*ClientRegistrationResponse, error) {
	redirectURIs, err := store.DecodeStringSlice(client.RedirectURIsJSON)
	if err != nil {
		return nil, err
	}
	grantTypes, err := store.DecodeStringSlice(client.GrantTypesJSON)
	if err != nil {
		return nil, err
	}
	responseTypes, err := store.DecodeStringSlice(client.ResponseTypesJSON)
	if err != nil {
		return nil, err
	}
	registrationAccessToken := ""
	if clientSecret == "" {
		registrationAccessToken = ""
	}
	return &ClientRegistrationResponse{ClientID: client.ClientID, ClientSecret: clientSecret, ClientIDIssuedAt: client.ClientIDIssuedAt, ClientSecretExpiresAt: client.ClientSecretExpiresAt, RegistrationClientURI: s.cfg.PublicBaseURL() + "/register/" + client.ClientID, RegistrationAccessToken: registrationAccessToken, TokenEndpointAuthMethod: client.TokenEndpointAuthMethod, RedirectURIs: redirectURIs, GrantTypes: grantTypes, ResponseTypes: responseTypes, ClientName: client.ClientName, ClientURI: ptrToString(client.ClientURI), SoftwareID: ptrToString(client.SoftwareID), SoftwareVersion: ptrToString(client.SoftwareVersion), DiscobotInstallationID: ptrToString(client.DiscobotInstallationID)}, nil
}

func parsePrivateKeyPEM(pemValue string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, fmt.Errorf("invalid private key pem")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected private key type")
	}
	return priv, nil
}

func validatePKCE(verifier string, challenge, method *string) error {
	if challenge == nil || *challenge == "" {
		return nil
	}
	if verifier == "" {
		return fmt.Errorf("missing code_verifier")
	}
	if method != nil && *method != "S256" {
		return fmt.Errorf("unsupported code challenge method")
	}
	expected := oauth2.S256ChallengeFromVerifier(verifier)
	if expected != *challenge {
		return fmt.Errorf("invalid code_verifier")
	}
	return nil
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func usernameFromEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return email
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func ptrToString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func strPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
