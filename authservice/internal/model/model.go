package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID        string    `gorm:"primaryKey;type:text" json:"id"`
	Email     string    `gorm:"uniqueIndex;not null;type:text" json:"email"`
	Username  string    `gorm:"not null;type:text" json:"username"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (User) TableName() string { return "users" }

func (u *User) BeforeCreate(_ *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	return nil
}

type Identity struct {
	ID             string    `gorm:"primaryKey;type:text" json:"id"`
	UserID         string    `gorm:"column:user_id;not null;type:text;index" json:"user_id"`
	Provider       string    `gorm:"not null;type:text;uniqueIndex:idx_provider_subject" json:"provider"`
	ProviderUserID string    `gorm:"column:provider_user_id;not null;type:text;uniqueIndex:idx_provider_subject" json:"provider_user_id"`
	Email          string    `gorm:"not null;type:text" json:"email"`
	Username       string    `gorm:"not null;type:text" json:"username"`
	CreatedAt      time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt      time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (Identity) TableName() string { return "identities" }

func (i *Identity) BeforeCreate(_ *gorm.DB) error {
	if i.ID == "" {
		i.ID = uuid.New().String()
	}
	return nil
}

type OAuthClient struct {
	ID                          string    `gorm:"primaryKey;type:text" json:"id"`
	ClientID                    string    `gorm:"column:client_id;not null;type:text;uniqueIndex" json:"client_id"`
	ClientSecretHash            string    `gorm:"column:client_secret_hash;not null;type:text" json:"-"`
	ClientName                  string    `gorm:"column:client_name;not null;type:text" json:"client_name"`
	ClientURI                   *string   `gorm:"column:client_uri;type:text" json:"client_uri,omitempty"`
	SoftwareID                  *string   `gorm:"column:software_id;type:text" json:"software_id,omitempty"`
	SoftwareVersion             *string   `gorm:"column:software_version;type:text" json:"software_version,omitempty"`
	DiscobotInstallationID      *string   `gorm:"column:discobot_installation_id;type:text" json:"discobot_installation_id,omitempty"`
	RedirectURIsJSON            []byte    `gorm:"column:redirect_uris_json;not null" json:"-"`
	GrantTypesJSON              []byte    `gorm:"column:grant_types_json;not null" json:"-"`
	ResponseTypesJSON           []byte    `gorm:"column:response_types_json;not null" json:"-"`
	TokenEndpointAuthMethod     string    `gorm:"column:token_endpoint_auth_method;not null;type:text" json:"token_endpoint_auth_method"`
	RegistrationAccessTokenHash string    `gorm:"column:registration_access_token_hash;not null;type:text" json:"-"`
	ClientIDIssuedAt            int64     `gorm:"column:client_id_issued_at;not null" json:"client_id_issued_at"`
	ClientSecretExpiresAt       int64     `gorm:"column:client_secret_expires_at;not null" json:"client_secret_expires_at"`
	RawMetadataJSON             []byte    `gorm:"column:raw_metadata_json" json:"-"`
	CreatedAt                   time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt                   time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (OAuthClient) TableName() string { return "oauth_clients" }

func (c *OAuthClient) BeforeCreate(_ *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return nil
}

type BrowserSession struct {
	ID        string    `gorm:"primaryKey;type:text" json:"id"`
	UserID    string    `gorm:"column:user_id;not null;type:text;index" json:"user_id"`
	TokenHash string    `gorm:"column:token_hash;not null;type:text;uniqueIndex" json:"-"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null;index" json:"expires_at"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (BrowserSession) TableName() string { return "browser_sessions" }

func (s *BrowserSession) BeforeCreate(_ *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

type AuthorizationCode struct {
	ID                  string     `gorm:"primaryKey;type:text" json:"id"`
	CodeHash            string     `gorm:"column:code_hash;not null;type:text;uniqueIndex" json:"-"`
	ClientID            string     `gorm:"column:client_id;not null;type:text;index" json:"client_id"`
	UserID              string     `gorm:"column:user_id;not null;type:text;index" json:"user_id"`
	RedirectURI         string     `gorm:"column:redirect_uri;not null;type:text" json:"redirect_uri"`
	Scope               string     `gorm:"not null;type:text" json:"scope"`
	Nonce               *string    `gorm:"type:text" json:"nonce,omitempty"`
	CodeChallenge       *string    `gorm:"column:code_challenge;type:text" json:"code_challenge,omitempty"`
	CodeChallengeMethod *string    `gorm:"column:code_challenge_method;type:text" json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time  `gorm:"column:expires_at;not null;index" json:"expires_at"`
	UsedAt              *time.Time `gorm:"column:used_at" json:"used_at,omitempty"`
	CreatedAt           time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

func (AuthorizationCode) TableName() string { return "authorization_codes" }

func (c *AuthorizationCode) BeforeCreate(_ *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return nil
}

type SigningKey struct {
	ID                      string    `gorm:"primaryKey;type:text" json:"id"`
	Kid                     string    `gorm:"column:kid;not null;type:text;uniqueIndex" json:"kid"`
	Algorithm               string    `gorm:"column:algorithm;not null;type:text" json:"algorithm"`
	PrivateKeyEncryptedData []byte    `gorm:"column:private_key_encrypted_data;not null" json:"-"`
	Active                  bool      `gorm:"column:active;not null;default:true;index" json:"active"`
	CreatedAt               time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt               time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (SigningKey) TableName() string { return "signing_keys" }

func (k *SigningKey) BeforeCreate(_ *gorm.DB) error {
	if k.ID == "" {
		k.ID = uuid.New().String()
	}
	return nil
}

// TLSCacheEntry stores encrypted TLS state blobs, such as ACME/autocert cache data.
type TLSCacheEntry struct {
	ID            string    `gorm:"primaryKey;type:text" json:"id"`
	CacheKey      string    `gorm:"column:cache_key;not null;type:text;uniqueIndex" json:"cache_key"`
	EncryptedData []byte    `gorm:"column:encrypted_data" json:"-"`
	CreatedAt     time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (TLSCacheEntry) TableName() string { return "tls_cache_entries" }

func (e *TLSCacheEntry) BeforeCreate(_ *gorm.DB) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	return nil
}

func AllModels() []any {
	return []any{
		&User{},
		&Identity{},
		&OAuthClient{},
		&BrowserSession{},
		&AuthorizationCode{},
		&SigningKey{},
		&TLSCacheEntry{},
	}
}
