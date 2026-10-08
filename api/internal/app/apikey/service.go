// Package apikey implements the application service for the apikey bounded context — orchestrates pkg/domain/apikey entities and cross-cutting concerns (audit, notifications, RBAC).
package apikey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
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
	legacy     []string          // earlier peppers that still verify (key rotation)
	membership MembershipChecker // nil → no member-lifecycle gate (tests only)
	holder     HolderPermissions // nil → scopes are not narrowed to the holder (tests only)
	// external decides whether an external member may create a key and how
	// long it may live (RFC-058). nil → no external-member rule (tests only).
	external ExternalKeyPolicy
	audit    *auditapp.AuditService
	logger   *logger.Logger
}

// ErrScopeNotHeld is returned (wrapped with shared.ErrForbidden) when a key is
// requested with a scope its creator does not hold.
var ErrScopeNotHeld = errors.New("scope not held by caller")

// SetAuditService wires audit logging for key create / revoke / delete.
func (s *Service) SetAuditService(a *auditapp.AuditService) { s.audit = a }

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

// SetLegacyPeppers sets earlier peppers whose key hashes keep verifying
// while APP_ENCRYPTION_KEY rotates (APP_ENCRYPTION_KEY_PREVIOUS). New keys
// are always hashed with the current pepper.
func (s *Service) SetLegacyPeppers(peppers ...string) {
	s.legacy = s.legacy[:0]
	for _, p := range peppers {
		if p != "" && p != s.pepper {
			s.legacy = append(s.legacy, p)
		}
	}
}

// KeyRehasher is implemented by a repository that can replace a key hash
// made with an earlier pepper (compare-and-swap on the old hash) and count
// the active keys still hashed with one.
type KeyRehasher interface {
	RehashKey(ctx context.Context, id shared.ID, oldHash, newHash string) (bool, error)
	CountKeysNotUnderPepper(ctx context.Context) (int, error)
}

// rehash stores newHash in place of oldHash. Best effort: a failure leaves
// the key verifying under the earlier pepper and is logged, never fatal.
func (s *Service) rehash(ctx context.Context, id shared.ID, oldHash, newHash string) {
	r, ok := s.repo.(KeyRehasher)
	if !ok {
		return
	}
	if changed, err := r.RehashKey(ctx, id, oldHash, newHash); err != nil {
		s.logger.Warn("api key re-hash under the current pepper failed", "key_id", id.String(), "error", err)
	} else if changed {
		s.logger.Info("api key re-hashed under the current pepper", "key_id", id.String())
	}
}

// SetMembershipChecker wires the membership gate used by Authenticate for
// user-scoped keys. When unset, key validity is decoupled from member lifecycle
// (acceptable only in tests) — always wire it in production.
func (s *Service) SetMembershipChecker(m MembershipChecker) { s.membership = m }

// HolderPermissions reports what a user CURRENTLY holds in a tenant. all=true
// means the user is an owner/admin, who bypass permission checks; otherwise
// perms is the user's explicit permission list (roles resolved now, not at
// key-mint time).
type HolderPermissions interface {
	HeldPermissions(ctx context.Context, tenantID, userID shared.ID) (all bool, perms []string, err error)
}

// SetHolderPermissions wires the resolver AuthenticateWithPermissions uses to
// bound a user-scoped key by its user's current permissions. Always wire it in
// production; without it a key keeps the scopes it was minted with even after
// its user is demoted.
func (s *Service) SetHolderPermissions(h HolderPermissions) { s.holder = h }

// ExternalKeyPolicy decides API keys for external members (RFC-058): an
// external member may create a key only when the trust with their home
// organization allows it, and a key never outlives the member's access.
type ExternalKeyPolicy interface {
	// APIKeyAllowance reports whether userID may create a key in tenantID
	// and, when their access ends, until when a key may live.
	APIKeyAllowance(ctx context.Context, tenantID, userID shared.ID) (allowed bool, until *time.Time, err error)
}

// SetExternalKeyPolicy wires the external-member rule.
func (s *Service) SetExternalKeyPolicy(p ExternalKeyPolicy) { s.external = p }

// ErrExternalNoAPIKeys refuses a key for an external member whose trust does
// not allow keys.
var ErrExternalNoAPIKeys = fmt.Errorf("%w: members from outside the organization cannot create API keys here", shared.ErrForbidden)

// checkExternalAllowance applies the external-member rule to a new key.
func (s *Service) checkExternalAllowance(ctx context.Context, tenantID shared.ID, userIDStr string, expiresInDays int) error {
	if s.external == nil || userIDStr == "" {
		return nil
	}
	userID, err := shared.IDFromString(userIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid user ID", shared.ErrValidation)
	}
	allowed, until, err := s.external.APIKeyAllowance(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrExternalNoAPIKeys
	}
	if until != nil && time.Now().Add(time.Duration(expiresInDays)*24*time.Hour).After(*until) {
		return fmt.Errorf("%w: the key may not outlive your access, which ends %s", shared.ErrValidation, until.UTC().Format("2006-01-02"))
	}
	return nil
}

// MaxExpiresInDays is the longest lifetime an API key may have (settings
// decision B14, 2026-10-04): every key expires, at most a year after it is
// minted. An organization may later tighten this; it may not loosen it.
const MaxExpiresInDays = 365

// ErrExpiryRequired is returned when a key is requested without an expiry or
// with one longer than MaxExpiresInDays.
var ErrExpiryRequired = fmt.Errorf("%w: expires_in_days must be between 1 and %d: every API key expires", shared.ErrValidation, MaxExpiresInDays)

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

	// CallerHolds reports whether the creating principal itself holds a
	// permission (owner/admin bypass included — the same check the route
	// gates use). When set, every requested scope must be held by the caller:
	// a key can never carry more authority than the person minting it. nil
	// skips the check (internal/system callers only).
	CallerHolds func(scope string) bool `json:"-"`

	// AuditContext, when set, records an api_key.created audit event.
	AuditContext *auditapp.AuditContext `json:"-"`
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
	if input.ExpiresInDays < 1 || input.ExpiresInDays > MaxExpiresInDays {
		return nil, ErrExpiryRequired
	}
	if err := s.checkExternalAllowance(ctx, tenantID, input.UserID, input.ExpiresInDays); err != nil {
		return nil, err
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
	// Pre-pepper rows have plain-SHA256 hashes; Authenticate falls back
	// to that hash on a miss.
	keyHash := crypto.HashTokenPeppered(plaintext, s.pepper)

	// Prefix for identification (first 8 chars of the oct_ key)
	prefix := plaintext[:8]

	id := shared.NewID()
	key := apikeydom.NewAPIKey(id, tenantID, input.Name, keyHash, prefix)

	if input.Description != "" {
		key.SetDescription(input.Description)
	}

	if len(input.Scopes) > 0 {
		// Reject typo'd / non-existent scopes at mint time. A scope that isn't a
		// real permission is dead weight at best and a silent least-privilege
		// misconfiguration at worst (the key would appear to grant access it can
		// never actually pass HasPermission for). Validated against the single
		// source of truth, permission.AllPermissions().
		for _, scope := range input.Scopes {
			if _, ok := permission.ParsePermission(scope); !ok {
				return nil, fmt.Errorf("%w: unknown scope %q", shared.ErrValidation, scope)
			}
			// Privilege-escalation guard: a member with api-keys:write could
			// otherwise mint a key carrying permissions they do not have
			// (e.g. team:admin-level scopes) and act beyond their own role.
			if input.CallerHolds != nil && !input.CallerHolds(scope) {
				return nil, fmt.Errorf("%w: %w: scope %q is not held by the caller",
					shared.ErrForbidden, ErrScopeNotHeld, scope)
			}
		}
		key.SetScopes(input.Scopes)
	}

	if input.RateLimit > 0 {
		key.SetRateLimit(input.RateLimit)
	}

	exp := key.CreatedAt().AddDate(0, 0, input.ExpiresInDays)
	key.SetExpiresAt(&exp)

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
		"name", logger.SanitizeValue(key.Name()),
		"prefix", prefix,
	)
	if s.audit != nil && input.AuditContext != nil {
		_ = s.audit.LogAPIKeyCreated(ctx, *input.AuditContext, key.ID().String(), key.Name(), key.Scopes())
	}

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

	// Candidate stored hashes, current pepper first: earlier peppers (a
	// rotated encryption key, APP_ENCRYPTION_KEY_PREVIOUS) and, when a pepper
	// is set, the plain SHA-256 of keys from before any pepper.
	candidates := []string{crypto.HashTokenPeppered(rawKey, s.pepper)}
	for _, p := range s.legacy {
		candidates = append(candidates, crypto.HashTokenPeppered(rawKey, p))
	}
	if s.pepper != "" {
		candidates = append(candidates, crypto.HashToken(rawKey))
	}
	var (
		key     *apikeydom.APIKey
		err     = shared.ErrNotFound
		matched string
	)
	for _, h := range candidates {
		if key, err = s.repo.GetByHash(ctx, h); err == nil {
			matched = h
			break
		}
		if !errors.Is(err, shared.ErrNotFound) {
			break
		}
	}
	if err != nil {
		return nil, apikeydom.ErrAPIKeyNotFound
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

	// A key that matched an earlier hash is re-hashed with the current
	// pepper, so it stops depending on APP_ENCRYPTION_KEY_PREVIOUS.
	if matched != candidates[0] {
		s.rehash(ctx, key.ID(), matched, candidates[0])
	}

	// Best-effort usage telemetry — a failure here must never fail auth.
	if terr := s.repo.TouchLastUsed(ctx, key.TenantID(), key.ID(), ip); terr != nil {
		s.logger.Debug("api key touch-last-used failed", "id", key.ID().String(), "error", terr.Error())
	}

	return key, nil
}

// AuthenticateWithPermissions is Authenticate plus the permissions the key may
// exercise on this request: its scopes, narrowed to what its user holds NOW.
// Scopes are checked against the creator only at mint time, so without this a
// key would keep a scope its user has since lost (a demotion or a role edit).
// An owner/admin holds every permission, so their keys keep all their scopes.
// A key with no user is bounded by its scopes alone. Failing to resolve the
// holder's permissions rejects the key, with the same error as every other
// failure.
func (s *Service) AuthenticateWithPermissions(ctx context.Context, rawKey, ip string) (*apikeydom.APIKey, []string, error) {
	key, err := s.Authenticate(ctx, rawKey, ip)
	if err != nil {
		return nil, nil, err
	}

	scopes := key.Scopes()
	uid := key.UserID()
	if uid == nil || s.holder == nil {
		return key, append([]string(nil), scopes...), nil
	}

	all, held, err := s.holder.HeldPermissions(ctx, key.TenantID(), *uid)
	if err != nil {
		s.logger.Warn("api key rejected: holder permissions unavailable",
			"key_id", key.ID().String(), "error", err.Error())
		return nil, nil, apikeydom.ErrAPIKeyNotFound
	}
	if all {
		return key, append([]string(nil), scopes...), nil
	}

	heldSet := make(map[string]struct{}, len(held))
	for _, p := range held {
		heldSet[p] = struct{}{}
	}
	effective := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		if _, ok := heldSet[sc]; ok {
			effective = append(effective, sc)
		}
	}
	return key, effective, nil
}

// ListInput represents input for listing API keys.
type ListInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	// UserID, when set, lists only the keys that belong to that user. The
	// handler sets it for callers who are not organization administrators:
	// they see their own keys, never other people's.
	UserID    string `json:"user_id" validate:"omitempty,uuid"`
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

	if input.UserID != "" {
		uid, err := shared.IDFromString(input.UserID)
		if err != nil {
			return apikeydom.ListResult{}, fmt.Errorf("%w: invalid user ID", shared.ErrValidation)
		}
		filter.UserID = &uid
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

	// OwnerID, when set, limits the call to that user's own keys: someone
	// else's key reads as not found. Empty means any key of the tenant (an
	// organization owner or administrator).
	OwnerID string `json:"-"`

	// AuditContext, when set, records an api_key.revoked audit event.
	AuditContext *auditapp.AuditContext `json:"-"`
}

// ownedBy reports whether ownerID may act on key: an empty ownerID (an
// owner or administrator) may act on any key of the tenant, anyone else only
// on a key bound to themselves.
func ownedBy(key *apikeydom.APIKey, ownerID string) bool {
	if ownerID == "" {
		return true
	}
	return key.UserID() != nil && key.UserID().String() == ownerID
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

	// Fetch with tenant isolation, then the ownership check: a member may
	// revoke only their own keys (settings audit A-M3). Someone else's key
	// reads as not found, as it does for Get.
	key, err := s.repo.GetByID(ctx, keyID, tenantID)
	if err != nil {
		return nil, err
	}
	if !ownedBy(key, input.OwnerID) {
		return nil, apikeydom.ErrAPIKeyNotFound
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
	if s.audit != nil && input.AuditContext != nil {
		_ = s.audit.LogAPIKeyRevoked(ctx, *input.AuditContext, key.ID().String(), key.Name())
	}

	return key, nil
}

// Delete deletes an API key. Tenant isolation enforced at DB level. A non-nil
// auditCtx records an api_key.deleted audit event.
func (s *Service) Delete(ctx context.Context, id, tenantIDStr string, auditCtx ...*auditapp.AuditContext) error {
	return s.DeleteOwned(ctx, id, tenantIDStr, "", auditCtx...)
}

// DeleteOwned deletes an API key that ownerID may act on: with an empty
// ownerID (an organization owner or administrator) any key of the tenant,
// otherwise only a key bound to ownerID. Someone else's key reads as not
// found (settings audit A-M3).
func (s *Service) DeleteOwned(ctx context.Context, id, tenantIDStr, ownerID string, auditCtx ...*auditapp.AuditContext) error {
	keyID, err := shared.IDFromString(id)
	if err != nil {
		return fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	if ownerID != "" {
		key, err := s.repo.GetByID(ctx, keyID, tenantID)
		if err != nil {
			return err
		}
		if !ownedBy(key, ownerID) {
			return apikeydom.ErrAPIKeyNotFound
		}
	}

	// DELETE WHERE id AND tenant_id.
	if err := s.repo.Delete(ctx, keyID, tenantID); err != nil {
		return err
	}

	s.logger.Info("api key deleted", "id", logger.SanitizeValue(id))
	if s.audit != nil && len(auditCtx) > 0 && auditCtx[0] != nil {
		_ = s.audit.LogAPIKeyDeleted(ctx, *auditCtx[0], keyID.String())
	}
	return nil
}
