// Package apikey implements the application service for the apikey bounded context — orchestrates pkg/domain/apikey entities and cross-cutting concerns (audit, notifications, RBAC).
package apikey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/crypto"
	apikeydom "github.com/openctemio/api/pkg/domain/apikey"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// keyPrefix is the required prefix of every OpenCTEM API key.
const keyPrefix = "oct_"

// errString renders an error for structured logging, tolerating nil.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Service provides business logic for API key management. pepper is
// the server-side secret mixed into every new key's stored hash via
// HMAC-SHA256 (pkg/crypto.HashTokenPeppered). Empty pepper falls
// back to plain SHA-256 — acceptable only in dev. When the DB is
// leaked but APP_ENCRYPTION_KEY is not, peppered rows resist offline
// brute-force against the leaked key_hash column (hashcat / rainbow
// tables without the HMAC key cannot recover the raw key).
type Service struct {
	repo       apikeydom.Repository
	pepper     string
	membership MembershipChecker // nil → no member-lifecycle gate (tests only)
	logger     *logger.Logger
}

// MembershipChecker reports whether a user still has an ACTIVE membership in a
// tenant. Injected so a suspended or removed member's `oct_` key stops
// authenticating immediately — the key's own status can't reflect
// member-lifecycle changes, so without this a removed member keeps API access.
type MembershipChecker interface {
	IsActiveMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
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

// SetMembershipChecker wires the membership gate used by Authenticate for
// user-scoped keys. When unset, key validity is decoupled from member lifecycle
// (acceptable only in tests) — always wire it in production.
func (s *Service) SetMembershipChecker(m MembershipChecker) { s.membership = m }

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

// Authenticate resolves a raw `oct_` API key to its active key entity, or a
// generic ErrAPIKeyNotFound. It hashes the presented key and looks it up; a
// peppered-hash miss falls back to the legacy plain-SHA256 hash so pre-pepper
// keys still authenticate. Every failure mode — wrong prefix, unknown key,
// revoked, or expired — returns the SAME error so a caller can't enumerate valid
// keys or distinguish states. On success it best-effort records last-used
// metadata (never blocks or fails auth on it).
func (s *Service) Authenticate(ctx context.Context, rawKey, ip string) (*apikeydom.APIKey, error) {
	if !strings.HasPrefix(rawKey, keyPrefix) {
		return nil, apikeydom.ErrAPIKeyNotFound
	}

	key, err := s.repo.GetByHash(ctx, crypto.HashTokenPeppered(rawKey, s.pepper))
	if err != nil {
		// Legacy rows (pre-pepper) stored a plain SHA-256 hash; retry with it
		// so old keys keep working after the pepper was introduced.
		if s.pepper != "" && errors.Is(err, shared.ErrNotFound) {
			key, err = s.repo.GetByHash(ctx, crypto.HashToken(rawKey))
		}
		if err != nil {
			return nil, apikeydom.ErrAPIKeyNotFound
		}
	}

	// IsActive covers both status (revoked/expired) and expiry timestamp.
	if !key.IsActive() {
		return nil, apikeydom.ErrAPIKeyNotFound
	}

	// Member-lifecycle gate: a user-scoped key must belong to a still-active
	// member. This makes member suspension/removal revoke the key immediately —
	// otherwise a removed member keeps API access until the key's own expiry.
	// Fail closed (reject) on a missing membership or any lookup error.
	if uid := key.UserID(); uid != nil && s.membership != nil {
		active, mErr := s.membership.IsActiveMember(ctx, key.TenantID(), *uid)
		if mErr != nil || !active {
			s.logger.Debug("api key rejected: member not active",
				"key_id", key.ID().String(), "error", errString(mErr))
			return nil, apikeydom.ErrAPIKeyNotFound
		}
	}

	// Best-effort usage telemetry — a failure here must never fail auth.
	if terr := s.repo.TouchLastUsed(ctx, key.ID(), ip); terr != nil {
		s.logger.Debug("api key touch-last-used failed", "id", key.ID().String(), "error", terr.Error())
	}

	return key, nil
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
