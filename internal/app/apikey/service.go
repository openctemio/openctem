package apikey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/openctemio/api/pkg/crypto"
	apikeydom "github.com/openctemio/api/pkg/domain/apikey"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// Service provides business logic for API key management. pepper is
// the server-side secret mixed into every new key's stored hash via
// HMAC-SHA256 (pkg/crypto.HashTokenPeppered). Empty pepper falls
// back to plain SHA-256 — acceptable only in dev. When the DB is
// leaked but APP_ENCRYPTION_KEY is not, peppered rows resist offline
// brute-force against the leaked key_hash column (hashcat / rainbow
// tables without the HMAC key cannot recover the raw key).
type Service struct {
	repo   apikeydom.Repository
	pepper string
	logger *logger.Logger
}

// NewService creates a new Service. pepper should be APP_ENCRYPTION_KEY
// (or a dedicated secret derived from it).
func NewService(repo apikeydom.Repository, pepper string, log *logger.Logger) *Service {
	return &Service{
		repo:   repo,
		pepper: pepper,
		logger: log.With("service", "apikey"),
	}
}

// CreateInput represents input for creating an API key.
type CreateInput struct {
	TenantID      string   `json:"tenant_id" validate:"required,uuid"`
	UserID        string   `json:"user_id" validate:"omitempty,uuid"`
	Name          string   `json:"name" validate:"required,min=1,max=255"`
	Description   string   `json:"description" validate:"max=1000"`
	Scopes        []string `json:"scopes" validate:"max=50"`
	RateLimit     int      `json:"rate_limit"`
	ExpiresInDays int      `json:"expires_in_days"`
	CreatedBy     string   `json:"created_by" validate:"omitempty,uuid"`
}

// CreateResult holds the created key and its plaintext (shown only once).
type CreateResult struct {
	Key       *apikeydom.APIKey
	Plaintext string // Only returned once on creation
}

// Create generates and stores a new API key.
func (s *Service) Create(ctx context.Context, input CreateInput) (*CreateResult, error) {
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

	// Hash for storage — peppered so that a DB leak without the
	// server-side pepper cannot brute-force the raw key offline.
	// Existing pre-fix rows have plain-SHA256 hashes and must be
	// verified with crypto.VerifyTokenHashAny when the validation
	// path is wired in (no active validator in this package yet —
	// F-9 follow-up).
	keyHash := crypto.HashTokenPeppered(plaintext, s.pepper)

	// Prefix for identification (first 8 chars of the oct_ key)
	prefix := plaintext[:8]

	id := shared.NewID()
	key := apikeydom.NewAPIKey(id, tenantID, input.Name, keyHash, prefix)

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

	return &CreateResult{
		Key:       key,
		Plaintext: plaintext,
	}, nil
}

// ListInput represents input for listing API keys.
type ListInput struct {
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
	Status    string `json:"status"`
	Search    string `json:"search"`
	Page      int    `json:"page"`
	PerPage   int    `json:"per_page"`
	SortBy    string `json:"sort_by"`
	SortOrder string `json:"sort_order"`
}

// List retrieves a paginated list of API keys.
func (s *Service) List(ctx context.Context, input ListInput) (apikeydom.ListResult, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return apikeydom.ListResult{}, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	filter := apikeydom.Filter{
		TenantID:  &tenantID,
		Search:    input.Search,
		Page:      input.Page,
		PerPage:   input.PerPage,
		SortBy:    input.SortBy,
		SortOrder: input.SortOrder,
	}

	if input.Status != "" {
		st := apikeydom.Status(input.Status)
		filter.Status = &st
	}

	return s.repo.List(ctx, filter)
}

// Get retrieves an API key by ID within a tenant.
func (s *Service) Get(ctx context.Context, id, tenantIDStr string) (*apikeydom.APIKey, error) {
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

// RevokeInput represents input for revoking an API key.
type RevokeInput struct {
	ID        string `json:"id" validate:"required,uuid"`
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
	RevokedBy string `json:"revoked_by" validate:"required,uuid"`
}

// Revoke revokes an API key.
func (s *Service) Revoke(ctx context.Context, input RevokeInput) (*apikeydom.APIKey, error) {
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

// Delete deletes an API key. Tenant isolation enforced at DB level.
func (s *Service) Delete(ctx context.Context, id, tenantIDStr string) error {
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
