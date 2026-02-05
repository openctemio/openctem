package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/openctemio/api/pkg/domain/apikey"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// APIKeyService provides business logic for API key management.
type APIKeyService struct {
	repo   apikey.Repository
	logger *logger.Logger
}

// NewAPIKeyService creates a new APIKeyService.
func NewAPIKeyService(repo apikey.Repository, log *logger.Logger) *APIKeyService {
	return &APIKeyService{
		repo:   repo,
		logger: log.With("service", "apikey"),
	}
}

// CreateAPIKeyInput represents input for creating an API key.
type CreateAPIKeyInput struct {
	TenantID      string   `json:"tenant_id" validate:"required,uuid"`
	UserID        string   `json:"user_id" validate:"omitempty,uuid"`
	Name          string   `json:"name" validate:"required,min=1,max=255"`
	Description   string   `json:"description" validate:"max=1000"`
	Scopes        []string `json:"scopes" validate:"max=50"`
	RateLimit     int      `json:"rate_limit"`
	ExpiresInDays int      `json:"expires_in_days"`
	CreatedBy     string   `json:"created_by" validate:"omitempty,uuid"`
}

// CreateAPIKeyResult holds the created key and its plaintext (shown only once).
type CreateAPIKeyResult struct {
	Key       *apikey.APIKey
	Plaintext string // Only returned once on creation
}

// CreateAPIKey generates and stores a new API key.
func (s *APIKeyService) CreateAPIKey(ctx context.Context, input CreateAPIKeyInput) (*CreateAPIKeyResult, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Generate random key bytes
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Format: oct_ + base64url encoded
	plaintext := "oct_" + base64.RawURLEncoding.EncodeToString(keyBytes)

	// Hash for storage
	hash := sha256.Sum256([]byte(plaintext))
	keyHash := fmt.Sprintf("%x", hash)

	// Prefix for identification (first 8 chars of the oct_ key)
	prefix := plaintext[:8]

	id := shared.NewID()
	key := apikey.NewAPIKey(id, tenantID, input.Name, keyHash, prefix)

	if input.Description != "" {
		key.SetDescription(input.Description)
	}

	if len(input.Scopes) > 0 {
		key.SetScopes(input.Scopes)
	}

	if input.RateLimit > 0 {
		key.SetRateLimit(input.RateLimit)
	}

	if input.ExpiresInDays > 0 {
		exp := key.CreatedAt().AddDate(0, 0, input.ExpiresInDays)
		key.SetExpiresAt(&exp)
	}

	if input.UserID != "" {
		uid, err := shared.IDFromString(input.UserID)
		if err == nil {
			key.SetUserID(&uid)
		}
	}

	if input.CreatedBy != "" {
		cbID, err := shared.IDFromString(input.CreatedBy)
		if err == nil {
			key.SetCreatedBy(cbID)
		}
	}

	if err := s.repo.Create(ctx, key); err != nil {
		return nil, err
	}

	s.logger.Info("api key created",
		"id", key.ID().String(),
		"tenant_id", key.TenantID().String(),
		"name", key.Name(),
		"prefix", prefix,
	)

	return &CreateAPIKeyResult{
		Key:       key,
		Plaintext: plaintext,
	}, nil
}

// ListAPIKeysInput represents input for listing API keys.
type ListAPIKeysInput struct {
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
	Status    string `json:"status"`
	Search    string `json:"search"`
	Page      int    `json:"page"`
	PerPage   int    `json:"per_page"`
	SortBy    string `json:"sort_by"`
	SortOrder string `json:"sort_order"`
}

// ListAPIKeys retrieves a paginated list of API keys.
func (s *APIKeyService) ListAPIKeys(ctx context.Context, input ListAPIKeysInput) (apikey.ListResult, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return apikey.ListResult{}, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	filter := apikey.Filter{
		TenantID:  &tenantID,
		Search:    input.Search,
		Page:      input.Page,
		PerPage:   input.PerPage,
		SortBy:    input.SortBy,
		SortOrder: input.SortOrder,
	}

	if input.Status != "" {
		st := apikey.Status(input.Status)
		filter.Status = &st
	}

	return s.repo.List(ctx, filter)
}

// GetAPIKey retrieves an API key by ID within a tenant.
func (s *APIKeyService) GetAPIKey(ctx context.Context, id, tenantIDStr string) (*apikey.APIKey, error) {
	keyID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	return s.repo.GetByID(ctx, keyID, tenantID)
}

// RevokeAPIKeyInput represents input for revoking an API key.
type RevokeAPIKeyInput struct {
	ID        string `json:"id" validate:"required,uuid"`
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
	RevokedBy string `json:"revoked_by" validate:"required,uuid"`
}

// RevokeAPIKey revokes an API key.
func (s *APIKeyService) RevokeAPIKey(ctx context.Context, input RevokeAPIKeyInput) (*apikey.APIKey, error) {
	keyID, err := shared.IDFromString(input.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Fetch with tenant isolation - no separate ownership check needed
	key, err := s.repo.GetByID(ctx, keyID, tenantID)
	if err != nil {
		return nil, err
	}

	revokedByID, err := shared.IDFromString(input.RevokedBy)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid revoked_by ID", shared.ErrValidation)
	}

	if err := key.Revoke(revokedByID); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, key); err != nil {
		return nil, err
	}

	s.logger.Info("api key revoked",
		"id", key.ID().String(),
		"name", key.Name(),
	)

	return key, nil
}

// DeleteAPIKey deletes an API key. Tenant isolation enforced at DB level.
func (s *APIKeyService) DeleteAPIKey(ctx context.Context, id, tenantIDStr string) error {
	keyID, err := shared.IDFromString(id)
	if err != nil {
		return fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Single query: DELETE WHERE id AND tenant_id - no separate GET needed
	if err := s.repo.Delete(ctx, keyID, tenantID); err != nil {
		return err
	}

	s.logger.Info("api key deleted", "id", id)
	return nil
}
