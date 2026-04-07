package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/obot-platform/discobot/authservice/internal/model"
)

var ErrNotFound = errors.New("record not found")

type Store struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Store {
	return &Store{db: db}
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	var user model.User
	if err := s.db.WithContext(ctx).First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	if err := s.db.WithContext(ctx).First(&user, "email = ?", email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *Store) GetIdentity(ctx context.Context, provider, providerUserID string) (*model.Identity, error) {
	var identity model.Identity
	if err := s.db.WithContext(ctx).First(&identity, "provider = ? AND provider_user_id = ?", provider, providerUserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &identity, nil
}

func (s *Store) CreateUser(ctx context.Context, user *model.User) error {
	return s.db.WithContext(ctx).Create(user).Error
}

func (s *Store) UpdateUser(ctx context.Context, user *model.User) error {
	return s.db.WithContext(ctx).Save(user).Error
}

func (s *Store) CreateIdentity(ctx context.Context, identity *model.Identity) error {
	return s.db.WithContext(ctx).Create(identity).Error
}

func (s *Store) UpdateIdentity(ctx context.Context, identity *model.Identity) error {
	return s.db.WithContext(ctx).Save(identity).Error
}

func (s *Store) CreateBrowserSession(ctx context.Context, session *model.BrowserSession) error {
	return s.db.WithContext(ctx).Create(session).Error
}

func (s *Store) GetBrowserSessionByToken(ctx context.Context, token string) (*model.BrowserSession, error) {
	var session model.BrowserSession
	if err := s.db.WithContext(ctx).First(&session, "token_hash = ?", hashString(token)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &session, nil
}

func (s *Store) DeleteBrowserSession(ctx context.Context, token string) error {
	return s.db.WithContext(ctx).Delete(&model.BrowserSession{}, "token_hash = ?", hashString(token)).Error
}

func (s *Store) CreateAuthorizationCode(ctx context.Context, code *model.AuthorizationCode) error {
	return s.db.WithContext(ctx).Create(code).Error
}

func (s *Store) GetAuthorizationCodeByCode(ctx context.Context, rawCode string) (*model.AuthorizationCode, error) {
	var code model.AuthorizationCode
	if err := s.db.WithContext(ctx).First(&code, "code_hash = ?", hashString(rawCode)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &code, nil
}

func (s *Store) UpdateAuthorizationCode(ctx context.Context, code *model.AuthorizationCode) error {
	return s.db.WithContext(ctx).Save(code).Error
}

func (s *Store) GetOAuthClientByClientID(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	var client model.OAuthClient
	if err := s.db.WithContext(ctx).First(&client, "client_id = ?", clientID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &client, nil
}

func (s *Store) GetOAuthClientByRegistrationAccessToken(ctx context.Context, token string) (*model.OAuthClient, error) {
	var client model.OAuthClient
	if err := s.db.WithContext(ctx).First(&client, "registration_access_token_hash = ?", hashString(token)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &client, nil
}

func (s *Store) CreateOAuthClient(ctx context.Context, client *model.OAuthClient) error {
	return s.db.WithContext(ctx).Create(client).Error
}

func (s *Store) GetActiveSigningKey(ctx context.Context) (*model.SigningKey, error) {
	var key model.SigningKey
	if err := s.db.WithContext(ctx).First(&key, "active = ?", true).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &key, nil
}

func (s *Store) CreateSigningKey(ctx context.Context, key *model.SigningKey) error {
	return s.db.WithContext(ctx).Create(key).Error
}

func HashString(value string) string {
	return hashString(value)
}

func DecodeStringSlice(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, err
	}
	return values, nil
}

func EncodeStringSlice(values []string) ([]byte, error) {
	return json.Marshal(values)
}

func Expired(expiresAt time.Time) bool {
	return time.Now().After(expiresAt)
}
