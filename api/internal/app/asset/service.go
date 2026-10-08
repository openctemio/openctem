// Package asset implements the application service for the asset bounded context — orchestrates pkg/domain/asset entities and cross-cutting concerns (audit, notifications, RBAC).
package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/metrics"

	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	assetgroupdom "github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

const (
	// scoringConfigCacheTTL is the TTL for in-memory scoring config cache.
	scoringConfigCacheTTL = 5 * time.Minute

	// recalcLockTTL is the TTL for the recalculation distributed lock.
	recalcLockTTL = 10 * time.Minute

	// recalcLockKeyPrefix is the Redis key prefix for recalculation locks.
	recalcLockKeyPrefix = "recalc:scoring:"

	// maxRecalcAssets is the maximum number of assets allowed for recalculation.
	maxRecalcAssets = 100000

	// scopeEvalTimeout bounds how long a detached scope-rule evaluation
	// goroutine waits on its downstream DB queries. Under a burst of
	// asset creates (bulk import, ingest pipeline) unbounded context
	// lets goroutines pile up and drain the process of memory.
	scopeEvalTimeout = 30 * time.Second
)

// scoringConfigEntry is a cached scoring config for a tenant.
type scoringConfigEntry struct {
	config    *assetdom.RiskScoringConfig
	expiresAt time.Time
}

// AssetService handles asset-related business operations.
type AssetService struct {
	repo              assetdom.Repository
	repoExtRepo       assetdom.RepositoryExtensionRepository
	assetGroupRepo    assetgroupdom.Repository // For recalculating group stats
	accessControlRepo accesscontrol.Repository // For Layer 2 data scope checks
	dataScope         *datascope.Enforcer      // Layer 2 enforcement on bulk-by-id paths (nil = unrestricted)
	scoringProvider   assetdom.ScoringConfigProvider
	redisClient       *redis.Client
	logger            *logger.Logger

	// In-memory scoring config cache (per-tenant, 5-min TTL)
	scoringCacheMu sync.RWMutex
	scoringCache   map[string]scoringConfigEntry // keyed by tenantID string

	// Scope rule evaluator callback (set by services.go wiring)
	scopeRuleEvaluator scope.RuleEvaluatorFunc

	// User matcher for resolving owner_ref (an email) to a tenant member, who
	// becomes the asset's primary owner in asset_owners.
	userMatcher UserMatcher

	// Lifecycle repository for RFC-004 Phase 0 snooze operations.
	// Optional — when nil, SnoozeLifecycle returns an unconfigured
	// error. Separated from the main Repository to avoid forcing
	// every mock in tests to add a snooze method they never use.
	lifecycleRepo assetdom.LifecycleRepository

	// State-history repository for the asset audit trail (appeared / status
	// changes). Optional and best-effort — when nil, recording is skipped and
	// failures never abort the originating operation. Kept off the main
	// Repository so test mocks don't need to implement it.
	stateHistoryRepo assetdom.StateHistoryRepository

	// businessContext resolves, per asset, the business-unit / business-service
	// criticality so risk scoring can score an asset's EFFECTIVE criticality —
	// MAX(own, its BU, the services it powers) — the SAME business-aligned rule
	// (assetdom.EffectiveCriticality) that finding-priority already applies.
	// Optional and nil-safe: when nil (or a lookup error, or an asset with no
	// BU/service membership) scoring falls back to the asset's own criticality,
	// byte-identical to the pre-business-alignment behavior. Floor only — the
	// effective value can raise a score, never lower it, and the asset's own
	// criticality column is never mutated.
	businessContext BusinessContextLookup
}

// UserMatcher resolves external references (email, username) to user IDs.
type UserMatcher interface {
	FindUserIDByEmail(ctx context.Context, tenantID shared.ID, email string) (*shared.ID, error)
}

// SetUserMatcher sets the user matcher for owner auto-resolution.
func (s *AssetService) SetUserMatcher(m UserMatcher) {
	s.userMatcher = m
}

// syncOwnerRefOwner keeps the owner derived from owner_ref in step with it.
// asset_owners is the only owner store: when ownerRef is the email of a member
// of the tenant, that member becomes a primary owner (source owner_ref);
// otherwise the row derived from a previous owner_ref is removed. Owners set by
// a person or a scope rule are never touched, and an owner_ref owner never
// grants data access. Best-effort: a failure is logged and never fails the
// asset write (the owner-resolution controller retries every 30 minutes).
func (s *AssetService) syncOwnerRefOwner(ctx context.Context, tenantID, assetID shared.ID, ownerRef string) {
	if s.accessControlRepo == nil {
		return
	}
	var matched *shared.ID
	if strings.Contains(ownerRef, "@") && s.userMatcher != nil {
		id, err := s.userMatcher.FindUserIDByEmail(ctx, tenantID, ownerRef)
		if err != nil {
			s.logger.Warn("owner_ref lookup failed", "asset_id", assetID.String(), "error", err)
			return
		}
		matched = id
	}
	if err := s.accessControlRepo.SyncOwnerRefOwner(ctx, tenantID, assetID, matched); err != nil {
		s.logger.Warn("owner_ref owner sync failed", "asset_id", assetID.String(), "error", err)
		return
	}
	if matched != nil {
		s.logger.Info("owner_ref matched a member", "asset_id", assetID.String(), "user_id", matched.String())
	}
}

// NewAssetService creates a new AssetService.
func NewAssetService(repo assetdom.Repository, log *logger.Logger) *AssetService {
	return &AssetService{
		repo:   repo,
		logger: log.With("service", "asset"),
	}
}

// SetRepositoryExtensionRepository sets the repository extension repository.
func (s *AssetService) SetRepositoryExtensionRepository(repo assetdom.RepositoryExtensionRepository) {
	s.repoExtRepo = repo
}

// SetAssetGroupRepository sets the asset group repository for recalculating stats.
func (s *AssetService) SetAssetGroupRepository(repo assetgroupdom.Repository) {
	s.assetGroupRepo = repo
}

// SetAccessControlRepository sets the access control repository for Layer 2 data scope checks.
func (s *AssetService) SetAccessControlRepository(repo accesscontrol.Repository) {
	s.accessControlRepo = repo
}

// SetScoringConfigProvider sets the scoring config provider for configurable risk scoring.
func (s *AssetService) SetScoringConfigProvider(provider assetdom.ScoringConfigProvider) {
	s.scoringProvider = provider
	s.scoringCache = make(map[string]scoringConfigEntry)
}

// SetRedisClient sets the Redis client for distributed locking.
func (s *AssetService) SetRedisClient(client *redis.Client) {
	s.redisClient = client
}

// SetScopeRuleEvaluator sets the scope rule evaluator callback.
// When set, asset create/update will trigger async scope rule evaluation.
func (s *AssetService) SetScopeRuleEvaluator(fn scope.RuleEvaluatorFunc) {
	s.scopeRuleEvaluator = fn
}

// SetLifecycleRepository wires the lifecycle-specific repository
// used by SnoozeLifecycle (RFC-004 Phase 0). Optional — callers
// that do not surface the snooze feature (tests, stubs) can leave
// this nil; the service returns a clear error in that case.
func (s *AssetService) SetLifecycleRepository(r assetdom.LifecycleRepository) {
	s.lifecycleRepo = r
}

// SetStateHistoryRepository wires the append-only asset state-history writer.
// Optional — when nil, state changes are simply not recorded.
func (s *AssetService) SetStateHistoryRepository(r assetdom.StateHistoryRepository) {
	s.stateHistoryRepo = r
}

// recordStateChange persists an asset state-change record on a best-effort
// basis: a nil repo or a write error never aborts the originating operation.
func (s *AssetService) recordStateChange(ctx context.Context, change *assetdom.AssetStateChange) {
	if s.stateHistoryRepo == nil || change == nil {
		return
	}
	if err := s.stateHistoryRepo.Create(ctx, change); err != nil {
		s.logger.Warn("failed to record asset state change", "error", err)
	}
}

// SnoozeLifecycle pauses the lifecycle worker on a single asset for
// the given duration and optionally reactivates it if currently
// stale or inactive. Duration <= 0 clears the snooze entirely (and
// never reactivates — clearing a snooze is a neutral operation,
// the worker takes over on its next run).
//
// Callers pass the desired duration (7/30/90 days, or custom). The
// service computes the exact paused-until timestamp from server
// time — clients never set a raw timestamp, which prevents
// clock-skew attacks and simplifies the HTTP contract.
func (s *AssetService) SnoozeLifecycle(
	ctx context.Context,
	tenantIDStr, assetIDStr string,
	duration time.Duration,
	reactivate bool,
) error {
	if s.lifecycleRepo == nil {
		return fmt.Errorf("%w: lifecycle repository not configured", shared.ErrInternal)
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	assetID, err := shared.IDFromString(assetIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid asset id", shared.ErrValidation)
	}

	var pausedUntil *time.Time
	actualReactivate := false
	if duration > 0 {
		t := time.Now().UTC().Add(duration)
		pausedUntil = &t
		actualReactivate = reactivate
	}
	// When duration <= 0 we are UN-snoozing; ignore the reactivate
	// flag so the operation is purely "clear the pause". If the
	// operator wants to reactivate the asset they can do so
	// explicitly via the regular status-change API.

	return s.lifecycleRepo.SnoozeLifecycle(ctx, tenantID, assetID, pausedUntil, actualReactivate)
}

// HasRepositoryExtensionRepository returns true if the repository extension repository is configured.
func (s *AssetService) HasRepositoryExtensionRepository() bool {
	return s.repoExtRepo != nil
}

// getScoringConfig returns the scoring config for a tenant, using cache when available.
// Falls back to legacy config if no provider is configured.
func (s *AssetService) getScoringConfig(ctx context.Context, tenantID shared.ID) *assetdom.RiskScoringConfig {
	if s.scoringProvider == nil {
		legacy := assetdom.LegacyRiskScoringConfig()
		return &legacy
	}

	key := tenantID.String()

	// Check cache (read lock)
	s.scoringCacheMu.RLock()
	if entry, ok := s.scoringCache[key]; ok && time.Now().Before(entry.expiresAt) {
		s.scoringCacheMu.RUnlock()
		return entry.config
	}
	s.scoringCacheMu.RUnlock()

	// Cache miss — fetch from provider
	config, err := s.scoringProvider.GetScoringConfig(ctx, tenantID)
	if err != nil {
		s.logger.Warn("failed to get scoring config, using legacy", "tenant_id", key, "error", err)
		legacy := assetdom.LegacyRiskScoringConfig()
		return &legacy
	}

	// Store in cache (write lock)
	s.scoringCacheMu.Lock()
	s.scoringCache[key] = scoringConfigEntry{
		config:    config,
		expiresAt: time.Now().Add(scoringConfigCacheTTL),
	}
	s.scoringCacheMu.Unlock()

	return config
}

// InvalidateScoringConfigCache removes the cached scoring config for a tenant.
// Call this when scoring settings are updated.
func (s *AssetService) InvalidateScoringConfigCache(tenantID shared.ID) {
	if s.scoringCache == nil {
		return
	}
	s.scoringCacheMu.Lock()
	delete(s.scoringCache, tenantID.String())
	s.scoringCacheMu.Unlock()
}

// CreateAssetInput represents the input for creating an asset.
type CreateAssetInput struct {
	TenantID    string         `validate:"omitempty,uuid"`
	Name        string         `validate:"required,min=1,max=255"`
	Type        string         `validate:"required,asset_type"`
	SubType     string         `validate:"omitempty,max=50"` // kind from the type's closed list, or a legacy input
	Criticality string         `validate:"required,criticality"`
	Scope       string         `validate:"omitempty,scope"`
	Exposure    string         `validate:"omitempty,exposure"`
	Description string         `validate:"max=1000"`
	Tags        []string       `validate:"max=20,dive,max=50"`
	OwnerRef    string         `validate:"max=500"` // Raw owner from external source
	Properties  map[string]any // JSONB properties (known fields auto-promoted to columns)
}

// DuplicateAssetError answers a create whose name (or an address the name
// correlates to) matches an asset that already exists in the tenant. It is a
// 409, never a silent merge. ExistingID is set only when the caller may see
// that asset (it is in their data scope); otherwise it is zero and the
// conflict reveals nothing about the asset.
type DuplicateAssetError struct {
	ExistingID shared.ID
}

func (e *DuplicateAssetError) Error() string {
	return "an asset with this name already exists"
}

// Unwrap makes the error a shared.ErrAlreadyExists.
func (e *DuplicateAssetError) Unwrap() error { return shared.ErrAlreadyExists }

// CreateOutcome says what a create request did.
type CreateOutcome struct {
	// Merged is true when the name or address matched an existing asset,
	// which was updated and returned instead of creating a new one.
	Merged bool
	// ChangedFields names the fields of the existing asset the merge
	// changed (never values).
	ChangedFields []string
}

// errCreateConflict answers a create whose name or address matches an asset
// the caller may not see: a plain conflict that reveals nothing about it.
var errCreateConflict = fmt.Errorf("%w: an asset with this name already exists", shared.ErrAlreadyExists)

// CreateAsset creates a new asset. When the name (or an address the name
// correlates to) matches an asset that already exists in the tenant, nothing
// is created or changed and the result is a *DuplicateAssetError: a create is
// not an edit, so it never merges into the existing asset. Ingest has its own
// merge path; this is the human/API create.
func (s *AssetService) CreateAsset(ctx context.Context, input CreateAssetInput) (*assetdom.Asset, error) {
	// Strip null bytes early — PostgreSQL rejects 0x00 in UTF-8
	input.Name = strings.ReplaceAll(input.Name, "\x00", "")
	input.Description = strings.ReplaceAll(input.Description, "\x00", "")

	// Platform-owned keys (crown jewel, business impact, aliases, discovery
	// fields) have their own endpoints and are never taken from properties.
	if err := RejectReservedProperties(input.Properties); err != nil {
		return nil, err
	}

	// Promote known fields from properties into proper columns.
	// Collectors may send sub_type, scope, etc. inside properties JSONB.
	input = PromoteKnownProperties(input)

	s.logger.Info("creating asset", "name", input.Name)

	// Resolve the input type (core type, alias or legacy sub-type) to the
	// stored (type, sub_type): aliases are never stored (RFC-042 §6.3.8).
	// A sub_type in the request wins over one promoted from properties.
	promotedSubType, _ := input.Properties["__promoted_sub_type"].(string)
	delete(input.Properties, "__promoted_sub_type")
	subTypeIn := input.SubType
	if subTypeIn == "" {
		subTypeIn = promotedSubType
	}
	resolved, err := assetdom.ResolveInputType(input.Type, subTypeIn)
	if err != nil {
		return nil, err
	}
	assetType, subType := resolved.Type, resolved.SubType
	// Flat properties (RFC-042 §6.3.10): a CTIS technical block a collector
	// sends (domain.dns_records, certificate.not_after, ...) fills the
	// stored type's keys, and the block goes.
	input.Properties = assetdom.NormalizeAssetProperties(assetType, subType, input.Properties)
	if err := rejectMisplacedProperties(assetType, subType, input.Properties); err != nil {
		return nil, err
	}

	criticality, err := assetdom.ParseCriticality(input.Criticality)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	// Parse tenant ID for existence check
	var tenantID shared.ID
	if input.TenantID != "" {
		tenantID, err = shared.IDFromString(input.TenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
	}

	// Normalize name before lookup so it matches existing normalized assets
	// (RFC-001). The sub-type is part of the identity key (RFC-043 section 10):
	// normalize, look up and create with the same (type, sub-type).
	normalizedName := assetdom.NormalizeName(input.Name, assetType, subType)
	if normalizedName != "" {
		input.Name = normalizedName
	}

	// An asset with the same name (or a correlated address) already exists:
	// a conflict, never a merge.
	if err := s.checkNotDuplicate(ctx, tenantID, input); err != nil {
		return nil, err
	}

	a, err := assetdom.NewAssetWithSubType(input.Name, assetType, subType, criticality)
	if err != nil {
		return nil, err
	}

	// Set tenant ID if provided (already parsed above)
	if !tenantID.IsZero() {
		a.SetTenantID(tenantID)
	}

	// Set scope if provided
	if input.Scope != "" {
		scope, err := assetdom.ParseScope(input.Scope)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		_ = a.UpdateScope(scope)
	}

	// Set exposure if provided
	if input.Exposure != "" {
		exposure, err := assetdom.ParseExposure(input.Exposure)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		_ = a.UpdateExposure(exposure)
	}

	if input.Description != "" {
		a.UpdateDescription(input.Description)
	}
	for _, tag := range input.Tags {
		a.AddTag(tag)
	}

	// Set properties (already cleaned by promoteKnownProperties), then what
	// the input type implied (provider, attributes) where nothing is set.
	if len(input.Properties) > 0 {
		a.SetProperties(input.Properties)
	}
	a.ApplyResolvedType(resolved)

	// Owner reference from an external source. The matching tenant member
	// becomes the primary owner once the asset is stored (syncOwnerRefOwner).
	if input.OwnerRef != "" {
		a.SetOwnerRef(input.OwnerRef)
	}

	// Calculate initial risk score using tenant-specific config. A brand-new
	// asset has no BU / business-service membership yet (memberships are linked
	// after creation), so effective criticality == own criticality here — the
	// business floor is applied on the next persist (update/patch/recalc).
	a.CalculateRiskScoreWithConfig(s.getScoringConfig(ctx, tenantID))

	if err := s.repo.Create(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to create asset: %w", err)
	}

	if input.OwnerRef != "" {
		s.syncOwnerRefOwner(ctx, tenantID, a.ID(), input.OwnerRef)
	}

	// Record an "appeared" event for the state-history audit trail (powers
	// shadow-IT detection, appearances, and the activity timeline).
	s.recordStateChange(ctx, assetdom.RecordAssetAppeared(tenantID, a.ID(), assetdom.ChangeSourceManual, "asset created"))

	// Evaluate scope rules for new asset (async — don't block response)
	if s.scopeRuleEvaluator != nil && len(a.Tags()) > 0 {
		assetID := a.ID()
		tid := tenantID
		tags := make([]string, len(a.Tags()))
		copy(tags, a.Tags())
		go func() {
			defer func() {
				if r := recover(); r != nil {
					metrics.RecordPanic("scope_evaluate")
					s.logger.Error("panic in scope rule evaluation", "asset_id", assetID.String(), "recover", r)
				}
			}()
			// Detach from request ctx (evaluator must outlive the HTTP
			// request) but cap at scopeEvalTimeout — if rule evaluation
			// hangs on a slow DB query, unbounded goroutines would pile
			// up under a burst of asset creates and exhaust memory.
			ctx, cancel := context.WithTimeout(context.Background(), scopeEvalTimeout)
			defer cancel()
			if err := s.scopeRuleEvaluator(ctx, tid, assetID, tags, nil); err != nil {
				s.logger.Warn("scope rule evaluation failed after asset create",
					"asset_id", assetID.String(), "error", err)
			}
		}()
	}

	s.logger.Info("asset created", "id", a.ID().String(), "name", logger.SanitizeValue(a.Name()))
	return a, nil
}

// promoteKnownProperties extracts well-known fields from Properties JSONB into their
// proper columns on CreateAssetInput. This allows collectors to send everything in
// properties (e.g., {"sub_type": "firewall", "vendor": "Cisco"}) and the system
// auto-promotes recognized fields while keeping the rest as JSONB metadata.
//
// Promoted fields (removed from Properties after extraction):
//   - sub_type → used to set entity.SubType
//   - type → resolved via TypeAliases (e.g., "firewall" → type=network, sub_type=firewall)
//   - scope, exposure, criticality → override top-level input fields if empty
//   - description → override if empty
//   - tags → merged with input.Tags
func PromoteKnownProperties(input CreateAssetInput) CreateAssetInput {
	if len(input.Properties) == 0 {
		return input
	}

	// Helper to extract and remove a string key
	extractStr := func(key string) string {
		if v, ok := input.Properties[key]; ok {
			delete(input.Properties, key)
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
		return ""
	}

	// sub_type: promote to dedicated field (stored on entity, not in JSONB)
	if st := extractStr("sub_type"); st != "" {
		// Store as a tag-like hint — service layer will call entity.SetSubType
		input.Properties["__promoted_sub_type"] = st
	}

	// type: a registry alias in properties (e.g. "firewall") names the type.
	// Any other value (a vendor's own type such as "lan") stays a property:
	// it used to overwrite input.Type and fail the request.
	if propType, ok := input.Properties["type"].(string); ok && propType != "" {
		if _, isAlias := assetdom.TypeAliases[assetdom.AssetType(strings.ToLower(strings.TrimSpace(propType)))]; isAlias {
			delete(input.Properties, "type")
			input.Type = propType
		}
	}

	// Override empty top-level fields from properties
	if input.Scope == "" {
		if s := extractStr("scope"); s != "" {
			input.Scope = s
		}
	}
	if input.Exposure == "" {
		if e := extractStr("exposure"); e != "" {
			input.Exposure = e
		}
	}
	if input.Description == "" {
		if d := extractStr("description"); d != "" {
			input.Description = d
		}
	}

	// Merge tags from properties
	if rawTags, ok := input.Properties["tags"]; ok {
		delete(input.Properties, "tags")
		switch t := rawTags.(type) {
		case []any:
			for _, v := range t {
				if s, ok := v.(string); ok && s != "" {
					input.Tags = append(input.Tags, s)
				}
			}
		case string:
			for _, s := range strings.Split(t, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					input.Tags = append(input.Tags, s)
				}
			}
		}
	}

	// Remove other well-known column names that shouldn't stay in JSONB
	for _, key := range []string{"name", "tenant_id", "criticality", "status", "owner_ref"} {
		delete(input.Properties, key)
	}

	// Normalize ALL camelCase property keys to snake_case.
	// Collectors may send either convention; we standardize on snake_case.
	// Generic converter handles any camelCase key automatically.
	normalizedProps := make(map[string]any, len(input.Properties))
	for key, val := range input.Properties {
		snakeKey := camelToSnakeCase(key)
		// If both camelCase and snake_case exist, prefer the snake_case value
		if snakeKey != key {
			if _, exists := normalizedProps[snakeKey]; exists {
				continue // canonical version already set, skip duplicate
			}
		}
		normalizedProps[snakeKey] = val
	}
	// One key per concept (RFC-042 §6.3.9): synonyms (ip, resolved_ips,
	// nameserver, technology, san, ...) fold into their canonical key.
	input.Properties = assetdom.NormalizeProperties(normalizedProps)

	// Normalize root_domain (strip trailing dot)
	if rd, ok := input.Properties["root_domain"].(string); ok && strings.HasSuffix(rd, ".") {
		input.Properties["root_domain"] = strings.TrimSuffix(rd, ".")
	}

	// Auto-detect subdomain: if type is "domain", check whether the name
	// looks like a subdomain based on domain level analysis.
	// Method 1: use root_domain property if provided by collector
	// Method 2: compute from domain name structure (handles .com.vn, .co.uk, etc.)
	if input.Type == "domain" {
		cleanName := strings.TrimSuffix(input.Name, ".")

		// Method 1: collector provides root_domain
		if rootDomain, ok := input.Properties["root_domain"].(string); ok && rootDomain != "" {
			cleanRoot := strings.TrimSuffix(rootDomain, ".")
			if cleanRoot != cleanName && strings.HasSuffix(cleanName, "."+cleanRoot) {
				input.Type = "subdomain"
			}
		}

		// Method 2: compute domain level from name structure
		// A root domain has exactly 1 label before the effective TLD
		// e.g., "ipa.com.vn" = root (1 label "ipa" before "com.vn")
		//        "sub.ipa.com.vn" = subdomain (2 labels before "com.vn")
		if input.Type == "domain" && isLikelySubdomain(cleanName) {
			input.Type = "subdomain"
		}
	}

	return input
}

// camelToSnakeCase converts a camelCase or PascalCase string to snake_case.
// Examples: "cpuCores" → "cpu_cores", "memoryGB" → "memory_gb", "apiType" → "api_type"
// Already snake_case or lowercase strings pass through unchanged.
func camelToSnakeCase(s string) string {
	if s == "" {
		return s
	}
	var result []byte
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			// Insert underscore before uppercase if:
			// - not the first character
			// - AND (previous char is lowercase OR next char is lowercase)
			// This handles: "memoryGB" → "memory_gb", "apiURL" → "api_url"
			if i > 0 {
				prev := s[i-1]
				if prev >= 'a' && prev <= 'z' {
					result = append(result, '_')
				} else if prev >= 'A' && prev <= 'Z' && i+1 < len(s) && s[i+1] >= 'a' && s[i+1] <= 'z' {
					result = append(result, '_')
				}
			}
			result = append(result, byte(r-'A'+'a'))
		} else {
			result = append(result, byte(r))
		}
	}
	return string(result)
}

// isLikelySubdomain checks if a domain name has more labels than a typical root domain.
// Uses known second-level domains (.com.vn, .co.uk, .com.au, etc.) to determine
// the effective TLD length. If there are >1 labels before the eTLD, it's a subdomain.
func isLikelySubdomain(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) < 3 {
		return false // "example.com" = 2 parts, not a subdomain
	}

	// Known second-level TLDs (eTLD+1 has 3+ parts for root domains)
	knownSLDs := map[string]bool{
		"com.vn": true, "net.vn": true, "org.vn": true, "edu.vn": true, "gov.vn": true,
		"co.uk": true, "org.uk": true, "ac.uk": true,
		"com.au": true, "net.au": true, "org.au": true,
		"co.jp": true, "or.jp": true, "ac.jp": true,
		"co.kr": true, "or.kr": true,
		"com.br": true, "org.br": true,
		"co.in": true, "org.in": true, "net.in": true,
		"com.sg": true, "org.sg": true,
		"com.my": true, "org.my": true,
		"co.th": true, "or.th": true,
		"com.tw": true, "org.tw": true,
		"co.id": true, "or.id": true,
		"com.ph": true, "org.ph": true,
		"co.nz": true, "org.nz": true,
		"co.za": true, "org.za": true,
	}

	// Check if last 2 parts form a known SLD
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if knownSLDs[last2] {
		// For .com.vn: "ipa.com.vn" = 3 parts = root; "sub.ipa.com.vn" = 4 parts = subdomain
		return len(parts) > 3
	}

	// For simple TLDs (.com, .net, .org, .io, etc.):
	// "example.com" = 2 parts = root; "sub.example.com" = 3 parts = subdomain
	return len(parts) > 2
}

// correlateByIPOrHostname tries to find an existing asset by IP or hostname properties.
// If input.Name looks like an IP (e.g., "10.0.1.5"), search for hosts with that IP in properties.
// If input.Name looks like a hostname, search for IP-named assets with that hostname in properties.
// Returns nil if no correlation found.
func (s *AssetService) correlateByIPOrHostname(ctx context.Context, tenantID shared.ID, input CreateAssetInput) *assetdom.Asset {
	name := input.Name

	// Try IP correlation: name is an IP → find host that has this IP
	if looksLikeIP(name) {
		found, err := s.repo.FindByIP(ctx, tenantID, name)
		if err != nil {
			s.logger.Warn("IP correlation lookup failed", "ip", name, "error", err)
			return nil
		}
		if found != nil {
			s.logger.Info("asset correlated by IP", "ip", name, "existing_id", found.ID().String(), "existing_name", found.Name())
			return found
		}
	}

	// Try hostname correlation: name is a hostname → find IP-named asset with this hostname
	if !looksLikeIP(name) && name != "" {
		found, err := s.repo.FindByHostname(ctx, tenantID, name)
		if err != nil {
			s.logger.Warn("hostname correlation lookup failed", "hostname", logger.SanitizeValue(name), "error", logger.SanitizeError(err))
			return nil
		}
		if found != nil {
			s.logger.Info("asset correlated by hostname",
				"hostname", logger.SanitizeValue(name), "id", found.ID().String())
			return found
		}
	}

	return nil
}

// looksLikeIP returns true if the string looks like an IPv4 or IPv6 address.
func looksLikeIP(s string) bool {
	// Simple check: contains dots and all segments are numeric (IPv4)
	// or contains colons (IPv6)
	if strings.Contains(s, ":") {
		return true // IPv6
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// checkNotDuplicate refuses a create whose name matches an existing asset of
// the tenant, or whose address correlates to one (IP/hostname correlation: an
// IP-named request finds a host with that IP, a hostname finds an IP-named
// asset with that hostname). The *DuplicateAssetError names the existing
// asset only when the caller may see it; a match outside the caller's data
// scope is a plain conflict that reveals nothing about it. The lookups are
// tenant-scoped, so another tenant's assets never match.
func (s *AssetService) checkNotDuplicate(ctx context.Context, tenantID shared.ID, input CreateAssetInput) error {
	existing, err := s.repo.GetByName(ctx, tenantID, input.Name)
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return fmt.Errorf("failed to check asset existence: %w", err)
	}
	if existing == nil {
		existing = s.correlateByIPOrHostname(ctx, tenantID, input)
	}
	if existing == nil {
		return nil
	}
	if s.dataScope.AssertAsset(ctx, tenantID, existing.ID()) != nil {
		return &DuplicateAssetError{}
	}
	return &DuplicateAssetError{ExistingID: existing.ID()}
}

// fullDataCaller reports whether the acting user is unrestricted through a
// has_full_data_access role, decided by the one enforcer (false without it).
func (s *AssetService) fullDataCaller(ctx context.Context, tenantID, actingUserID string) (bool, error) {
	if s.dataScope == nil {
		return false, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return false, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	return s.dataScope.FullData(ctx, tid, actingUserID)
}

// SetDataScope wires the Layer 2 data-scope enforcer used on bulk-by-id
// writes. By-id routes are guarded at the HTTP layer (DataScopeGuard).
func (s *AssetService) SetDataScope(e *datascope.Enforcer) {
	s.dataScope = e
}

// GetAsset retrieves an asset by ID within a tenant.
// Security: Requires tenantID to prevent cross-tenant data access.
func (s *AssetService) GetAsset(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error) {
	return s.GetAssetWithScope(ctx, tenantID, assetID, "", true)
}

// GetAssetInCallerScope is GetAsset for a path keyed on an asset that the
// route guard does not see (another resource's URL, a query parameter): it
// also answers shared.ErrNotFound when the request's caller may not see the
// asset, through the data-scope enforcer.
func (s *AssetService) GetAssetInCallerScope(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error) {
	a, err := s.GetAsset(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if s.dataScope != nil {
		if err := s.dataScope.AssertAsset(ctx, a.TenantID(), a.ID()); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// GetAssetWithScope retrieves an asset with optional data scope enforcement.
// Non-admin users with group assignments can only access assets in their groups.
// Security: fail-closed — any error during scope check denies access.
// Returns ErrNotFound (not ErrForbidden) to prevent information disclosure.
func (s *AssetService) GetAssetWithScope(ctx context.Context, tenantID, assetID, actingUserID string, isAdmin bool) (*assetdom.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	// A role with has_full_data_access bypasses Layer 2 like an admin.
	if !isAdmin && actingUserID != "" {
		full, ferr := s.fullDataCaller(ctx, tenantID, actingUserID)
		if ferr != nil {
			s.logger.Error("failed to check full data access", "error", ferr)
			return nil, shared.ErrNotFound // fail-closed
		}
		isAdmin = full
	}

	// Layer 2: Data Scope check for non-admin users
	if !isAdmin && actingUserID != "" && s.accessControlRepo != nil {
		userID, parseErr := shared.IDFromString(actingUserID)
		if parseErr != nil {
			s.logger.Warn("failed to parse acting user ID for scope check", "actingUserID", actingUserID, "error", parseErr)
			return nil, shared.ErrNotFound // fail-closed
		}

		// The asset must be in the user's scope rows; a member with none
		// sees nothing (fail closed). 404, so existence is not confirmed.
		canAccess, accessErr := s.accessControlRepo.CanAccessAsset(ctx, userID, parsedID)
		if accessErr != nil {
			s.logger.Error("failed to check asset access", "error", accessErr)
			return nil, shared.ErrNotFound // fail-closed
		}
		if !canAccess {
			return nil, shared.ErrNotFound
		}
	}

	return a, nil
}

// UpdateAssetInput represents the input for updating an asset.
type UpdateAssetInput struct {
	Name        *string  `validate:"omitempty,min=1,max=255"`
	Criticality *string  `validate:"omitempty,criticality"`
	Scope       *string  `validate:"omitempty,scope"`
	Exposure    *string  `validate:"omitempty,exposure"`
	Description *string  `validate:"omitempty,max=1000"`
	OwnerRef    *string  `validate:"omitempty,max=500"` // Free-text owner reference
	Tags        []string `validate:"omitempty,max=20,dive,max=50"`
	// SubType changes the kind within the asset's type (closed list, or a
	// legacy input of the same type). "" clears it. Nil = leave unchanged.
	SubType *string `validate:"omitempty,max=50"`
	// Properties patches per-type metadata. Merged (not replaced) into the
	// asset's existing properties so keys like business_impact_score are preserved.
	Properties map[string]any
	// CIA impact rating (CTEM Scoping critical-asset register). Each is
	// low | moderate | high; an empty string clears the rating. Nil = leave
	// unchanged.
	ImpactConfidentiality *string `validate:"omitempty,impact_rating"`
	ImpactIntegrity       *string `validate:"omitempty,impact_rating"`
	ImpactAvailability    *string `validate:"omitempty,impact_rating"`
}

// UpdateAsset updates an existing asset.
// Security: Requires tenantID to prevent cross-tenant data modification.
func (s *AssetService) UpdateAsset(ctx context.Context, assetID string, tenantID string, input UpdateAssetInput) (*assetdom.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	// GetByID with tenantID automatically enforces tenant isolation
	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	// Platform-owned keys cannot be changed through properties; an
	// unchanged echo of the stored value is dropped.
	if input.Properties != nil {
		if err := stripUnchangedReservedProperties(input.Properties, a.Properties()); err != nil {
			return nil, err
		}
		if err := rejectMisplacedProperties(a.Type(), a.SubType(), input.Properties); err != nil {
			return nil, err
		}
	}

	oldName := a.Name()
	if input.Name != nil {
		if err := a.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}

	if input.Criticality != nil {
		criticality, err := assetdom.ParseCriticality(*input.Criticality)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		if err := a.UpdateCriticality(criticality); err != nil {
			return nil, err
		}
	}

	if input.Scope != nil {
		scope, err := assetdom.ParseScope(*input.Scope)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		if err := a.UpdateScope(scope); err != nil {
			return nil, err
		}
	}

	oldExposure := a.Exposure()
	if input.Exposure != nil {
		exposure, err := assetdom.ParseExposure(*input.Exposure)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		if err := a.UpdateExposure(exposure); err != nil {
			return nil, err
		}
	}

	if input.Description != nil {
		a.UpdateDescription(*input.Description)
	}

	ownerRefChanged := false
	if input.OwnerRef != nil {
		ownerRefChanged = *input.OwnerRef != a.OwnerRef()
		a.SetOwnerRef(*input.OwnerRef)
	}

	oldSubType := a.SubType()
	if input.SubType != nil {
		if err := applySubTypeChange(a, *input.SubType); err != nil {
			return nil, err
		}
	}

	// CIA impact rating (CTEM Scoping critical-asset register).
	if input.ImpactConfidentiality != nil {
		rating, err := assetdom.ParseImpactRating(*input.ImpactConfidentiality)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		if err := a.SetImpactConfidentiality(rating); err != nil {
			return nil, err
		}
	}
	if input.ImpactIntegrity != nil {
		rating, err := assetdom.ParseImpactRating(*input.ImpactIntegrity)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		if err := a.SetImpactIntegrity(rating); err != nil {
			return nil, err
		}
	}
	if input.ImpactAvailability != nil {
		rating, err := assetdom.ParseImpactRating(*input.ImpactAvailability)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		if err := a.SetImpactAvailability(rating); err != nil {
			return nil, err
		}
	}

	// Capture old tags before replacement (for scope rule evaluation)
	var oldTags []string
	if input.Tags != nil {
		oldTags = make([]string, len(a.Tags()))
		copy(oldTags, a.Tags())

		for _, tag := range a.Tags() {
			a.RemoveTag(tag)
		}
		for _, tag := range input.Tags {
			a.AddTag(tag)
		}
	}

	// Patch per-type metadata. Merge into existing properties (don't replace)
	// so keys written elsewhere — e.g. business_impact_score — are not wiped.
	if input.Properties != nil {
		merged := a.Properties()
		if merged == nil {
			merged = make(map[string]any, len(input.Properties))
		}
		for k, v := range input.Properties {
			merged[k] = v
		}
		a.SetProperties(assetdom.NormalizeAssetProperties(a.Type(), a.SubType(), merged))
	}

	// Recalculate risk score after updates using the asset's effective
	// (BU/service-aligned) criticality. Nil-safe fallback to own criticality.
	s.scoreAsset(ctx, parsedTenantID, a)

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to update asset: %w", err)
	}

	// A changed owner_ref replaces the owner derived from the old one (an
	// emptied or unmatched owner_ref just removes it).
	if ownerRefChanged {
		s.syncOwnerRefOwner(ctx, parsedTenantID, parsedID, a.OwnerRef())
	}

	// Recalculate affected group stats (risk_score, finding_count, etc.)
	s.recalculateAffectedGroups(ctx, parsedID)

	if a.Name() != oldName {
		s.recordStateChange(ctx, assetdom.RecordFieldChange(parsedTenantID, parsedID,
			assetdom.StateChangeRenamed, "name", oldName, a.Name(), assetdom.ChangeSourceManual, nil))
	}
	if a.SubType() != oldSubType {
		s.recordStateChange(ctx, assetdom.RecordFieldChange(parsedTenantID, parsedID,
			assetdom.StateChangeReclassified, "sub_type", oldSubType, a.SubType(), assetdom.ChangeSourceManual, nil))
	}

	// A manual exposure change (e.g. an operator marking an asset public) is
	// part of "what changed" in the attack surface, same as a scan-driven one.
	if a.Exposure() != oldExposure {
		s.recordStateChange(ctx, assetdom.RecordFieldChange(parsedTenantID, parsedID,
			assetdom.StateChangeExposureChanged, "exposure",
			oldExposure.String(), a.Exposure().String(), assetdom.ChangeSourceManual, nil))
	}

	// Evaluate scope rules if tags changed (async — don't block response)
	if s.scopeRuleEvaluator != nil && input.Tags != nil && !tagsEqual(oldTags, a.Tags()) {
		assetID := a.ID()
		tid := parsedTenantID
		tags := make([]string, len(a.Tags()))
		copy(tags, a.Tags())
		go func() {
			defer func() {
				if r := recover(); r != nil {
					metrics.RecordPanic("scope_evaluate")
					s.logger.Error("panic in scope rule evaluation", "asset_id", assetID.String(), "recover", r)
				}
			}()
			// Detach from request ctx (evaluator must outlive the HTTP
			// request) but cap at scopeEvalTimeout — if rule evaluation
			// hangs on a slow DB query, unbounded goroutines would pile
			// up under a burst of asset creates and exhaust memory.
			ctx, cancel := context.WithTimeout(context.Background(), scopeEvalTimeout)
			defer cancel()
			if err := s.scopeRuleEvaluator(ctx, tid, assetID, tags, nil); err != nil {
				s.logger.Warn("scope rule evaluation failed after asset update",
					"asset_id", assetID.String(), "error", err)
			}
		}()
	}

	s.logger.Info("asset updated", "id", a.ID().String())
	return a, nil
}

// applySubTypeChange sets a requested sub-type on an existing asset. The
// value is resolved against the asset's own type: a legacy input of that
// type is mapped, anything that would change the type is refused (the type
// of an existing asset is not editable).
func applySubTypeChange(a *assetdom.Asset, requested string) error {
	if strings.TrimSpace(requested) == "" {
		return a.ChangeSubType("")
	}
	resolved, err := assetdom.ResolveInputType(string(a.Type()), requested)
	if err != nil {
		return err
	}
	if resolved.Type != a.Type() {
		return fmt.Errorf("%w: sub_type %q belongs to asset type %q, not %q; the type of an asset cannot be changed",
			shared.ErrValidation, requested, resolved.Type, a.Type())
	}
	if err := a.ChangeSubType(resolved.SubType); err != nil {
		return err
	}
	a.ApplyResolvedType(resolved)
	return nil
}

// SaveAsset persists changes to an asset entity directly.
// Used by handlers that modify the entity and need to persist without going through UpdateAssetInput.
func (s *AssetService) SaveAsset(ctx context.Context, a *assetdom.Asset) error {
	return s.repo.Update(ctx, a)
}

// UpdateCrownJewel marks or unmarks an asset of the tenant as a crown jewel
// and records its business impact, then returns the stored asset. The flag
// is the assets.is_crown_jewel column; this is its only writer.
func (s *AssetService) UpdateCrownJewel(ctx context.Context, tenantID, assetID string, isCrownJewel bool, impactScore float64, impactNotes string) (*assetdom.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	if err := s.repo.SetCrownJewel(ctx, parsedTenantID, parsedID, isCrownJewel, impactScore, impactNotes); err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, parsedTenantID, parsedID)
}

// DeleteAsset deletes an asset by ID on behalf of a person (actorID, may be
// empty). An asset that has findings is refused with *assetdom.HasFindingsError
// (a conflict): its history must be kept, so it should be archived instead.
// Otherwise the asset is soft-deleted (see the repository's Delete).
// Security: Requires tenantID to prevent cross-tenant deletion.
func (s *AssetService) DeleteAsset(ctx context.Context, assetID, tenantID, actorID string) error {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return shared.ErrNotFound
	}

	var deletedBy *shared.ID
	if actor, aerr := shared.IDFromString(actorID); aerr == nil {
		deletedBy = &actor
	}

	// Get groups containing this asset BEFORE deletion (the delete detaches
	// it from them).
	var groupIDs []shared.ID
	if s.assetGroupRepo != nil {
		groupIDs, _ = s.assetGroupRepo.GetGroupIDsByAssetID(ctx, parsedID)
	}

	// Delete with tenantID automatically enforces tenant isolation
	if err := s.repo.Delete(ctx, parsedTenantID, parsedID, deletedBy); err != nil {
		return err
	}

	// Recalculate affected group stats after deletion
	for _, groupID := range groupIDs {
		if err := s.assetGroupRepo.RecalculateCounts(ctx, groupID); err != nil {
			s.logger.Warn("failed to recalculate group stats after asset deletion",
				"assetID", assetID, "groupID", groupID, "error", err)
		}
	}

	s.logger.Info("asset deleted", "id", assetID)
	return nil
}

// recalculateAffectedGroups recalculates stats for groups containing the asset.
func (s *AssetService) recalculateAffectedGroups(ctx context.Context, assetID shared.ID) {
	if s.assetGroupRepo == nil {
		return
	}

	groupIDs, err := s.assetGroupRepo.GetGroupIDsByAssetID(ctx, assetID)
	if err != nil {
		s.logger.Warn("failed to get groups for asset", "assetID", assetID, "error", err)
		return
	}

	for _, groupID := range groupIDs {
		if err := s.assetGroupRepo.RecalculateCounts(ctx, groupID); err != nil {
			s.logger.Warn("failed to recalculate group stats",
				"assetID", assetID, "groupID", groupID, "error", err)
		}
	}
}

// ListAssetsInput represents the input for listing assets.
type ListAssetsInput struct {
	TenantID         string              `validate:"omitempty,uuid"`
	Name             string              `validate:"max=255"`
	Types            []string            `validate:"max=20,dive,asset_type"`
	Criticalities    []string            `validate:"max=5,dive,criticality"`
	Statuses         []string            `validate:"max=3,dive,status"`
	Scopes           []string            `validate:"max=6,dive,scope"`
	Exposures        []string            `validate:"max=5,dive,exposure"`
	Tags             []string            `validate:"max=20,dive,max=50"`
	Search           string              `validate:"max=255"` // Full-text search across name and description
	MinRiskScore     *int                `validate:"omitempty,min=0,max=100"`
	MaxRiskScore     *int                `validate:"omitempty,min=0,max=100"`
	HasFindings      *bool               // Filter by whether asset has findings
	IsCrownJewel     *bool               // Filter crown jewel assets
	SubType          *string             // Filter by sub_type
	PropertiesFilter map[string][]string // Filter by JSONB properties (AND across keys, OR within values)

	// CTEM inventory dimensions (all optional; back-compat when unset).
	BusinessUnitIDs      []string `validate:"max=50,dive,uuid"`
	HasOwner             *bool    // Assets with/without an assigned owner
	DataClassifications  []string `validate:"max=5,dive,oneof=public internal confidential restricted secret"`
	IsControlPlane       *bool    // Asset is a control-plane dependency
	IsInternetAccessible *bool    // Asset is internet-reachable
	Environments         []string `validate:"max=5,dive,oneof=production staging development testing dr"`
	Providers            []string `validate:"max=20,dive,max=50"`
	LastSeenAfter        *time.Time
	LastSeenBefore       *time.Time
	// Attribution: attribution states (confirmed, needs_review, candidate,
	// dependency, monitor_only, rejected) or the aliases unknown, unconfirmed
	// and approved (RFC-036). Validated by attribution.ParseFilter.
	Attribution []string `validate:"max=9,dive,max=20"`
	// CoveredBy: assets the scope join confirmed through this scope entry
	// (RFC-054 §4.3), the link behind "N assets confirmed".
	CoveredBy string `validate:"omitempty,uuid"`

	Sort    string `validate:"max=100"` // Sort field (e.g., "-created_at", "name")
	Page    int    `validate:"min=0"`
	PerPage int    `validate:"min=0,max=100"`

	// Layer 2: Data Scope
	ActingUserID string // From JWT context
	IsAdmin      bool   // True for owner/admin (bypasses data scope)
}

// ListAssets retrieves assets with filtering, sorting, and pagination.
func (s *AssetService) ListAssets(ctx context.Context, input ListAssetsInput) (pagination.Result[*assetdom.Asset], error) {
	filter := assetdom.NewFilter()

	// Tenant filter
	if input.TenantID != "" {
		filter = filter.WithTenantID(input.TenantID)
	}

	// Name filter
	if input.Name != "" {
		filter = filter.WithName(input.Name)
	}

	// Asset types filter
	if len(input.Types) > 0 {
		types := make([]assetdom.AssetType, 0, len(input.Types))
		for _, t := range input.Types {
			if parsed, err := assetdom.ParseAssetType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter = filter.WithTypes(types...)
	}

	// Criticalities filter
	if len(input.Criticalities) > 0 {
		criticalities := make([]assetdom.Criticality, 0, len(input.Criticalities))
		for _, c := range input.Criticalities {
			if parsed, err := assetdom.ParseCriticality(c); err == nil {
				criticalities = append(criticalities, parsed)
			}
		}
		filter = filter.WithCriticalities(criticalities...)
	}

	// Statuses filter
	if len(input.Statuses) > 0 {
		statuses := make([]assetdom.Status, 0, len(input.Statuses))
		for _, st := range input.Statuses {
			if parsed, err := assetdom.ParseStatus(st); err == nil {
				statuses = append(statuses, parsed)
			}
		}
		filter = filter.WithStatuses(statuses...)
	}

	// Scopes filter
	if len(input.Scopes) > 0 {
		scopes := make([]assetdom.Scope, 0, len(input.Scopes))
		for _, sc := range input.Scopes {
			if parsed, err := assetdom.ParseScope(sc); err == nil {
				scopes = append(scopes, parsed)
			}
		}
		filter = filter.WithScopes(scopes...)
	}

	// Exposures filter
	if len(input.Exposures) > 0 {
		exposures := make([]assetdom.Exposure, 0, len(input.Exposures))
		for _, ex := range input.Exposures {
			if parsed, err := assetdom.ParseExposure(ex); err == nil {
				exposures = append(exposures, parsed)
			}
		}
		filter = filter.WithExposures(exposures...)
	}

	// Tags filter
	if len(input.Tags) > 0 {
		filter = filter.WithTags(input.Tags...)
	}

	// Search filter
	if input.Search != "" {
		filter = filter.WithSearch(input.Search)
	}

	// Risk score filters
	if input.MinRiskScore != nil {
		filter = filter.WithMinRiskScore(*input.MinRiskScore)
	}
	if input.MaxRiskScore != nil {
		filter = filter.WithMaxRiskScore(*input.MaxRiskScore)
	}

	// Has findings filter
	if input.HasFindings != nil {
		filter = filter.WithHasFindings(*input.HasFindings)
	}

	// Crown jewel filter
	if input.IsCrownJewel != nil {
		filter.IsCrownJewel = input.IsCrownJewel
	}

	// Sub-type filter
	if input.SubType != nil {
		filter.SubType = input.SubType
	}

	// Properties filter (JSONB containment)
	if len(input.PropertiesFilter) > 0 {
		filter = filter.WithPropertiesFilter(input.PropertiesFilter)
	}

	// CTEM inventory dimensions.
	if len(input.BusinessUnitIDs) > 0 {
		filter = filter.WithBusinessUnitIDs(input.BusinessUnitIDs...)
	}
	if input.HasOwner != nil {
		filter = filter.WithHasOwner(*input.HasOwner)
	}
	if af, given, err := attribution.ParseFilter(input.Attribution); err != nil {
		return pagination.Result[*assetdom.Asset]{}, fmt.Errorf("%w: %s", shared.ErrValidation, err.Error())
	} else if given {
		filter = filter.WithAttribution(af)
	}
	if input.CoveredBy != "" {
		id, err := shared.IDFromString(input.CoveredBy)
		if err != nil {
			return pagination.Result[*assetdom.Asset]{}, fmt.Errorf("%w: covered_by must be a scope entry id", shared.ErrValidation)
		}
		filter.CoveredByScopeTarget = &id
	}
	if len(input.DataClassifications) > 0 {
		filter = filter.WithDataClassifications(input.DataClassifications...)
	}
	if input.IsControlPlane != nil {
		filter = filter.WithIsControlPlane(*input.IsControlPlane)
	}
	if input.IsInternetAccessible != nil {
		filter = filter.WithIsInternetAccessible(*input.IsInternetAccessible)
	}
	if len(input.Environments) > 0 {
		filter = filter.WithEnvironments(input.Environments...)
	}
	if len(input.Providers) > 0 {
		// Preserve exact stored provider values (provider is a free VARCHAR;
		// don't collapse unknowns to "other" the way ParseProvider would).
		providers := make([]assetdom.Provider, 0, len(input.Providers))
		for _, p := range input.Providers {
			if p != "" {
				providers = append(providers, assetdom.Provider(p))
			}
		}
		filter = filter.WithProviders(providers...)
	}
	if input.LastSeenAfter != nil {
		filter = filter.WithLastSeenAfter(*input.LastSeenAfter)
	}
	if input.LastSeenBefore != nil {
		filter = filter.WithLastSeenBefore(*input.LastSeenBefore)
	}

	// Layer 2: Data Scope - non-admin users only see assets in their groups
	access, err := s.listAccessScope(ctx, input.TenantID, input.ActingUserID, input.IsAdmin)
	if err != nil {
		return pagination.Result[*assetdom.Asset]{}, err
	}
	filter.DataScopeUserID = access.DataScopeUserID

	// Build list options with sorting
	opts := assetdom.NewListOptions()
	if input.Sort != "" {
		sortOpt := pagination.NewSortOption(assetdom.AllowedSortFields()).Parse(input.Sort)
		opts = opts.WithSort(sortOpt)
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.List(ctx, filter, opts, page)
}

// listAccessScope is the Layer-2 data scope the asset list applies, shared by
// the list, the stats and the property facets so the counts a user sees match
// what they can list. Admins and callers with no user (API keys) are not
// narrowed. An acting user id that does not parse is refused (fail closed)
// instead of silently dropping the scope.
func (s *AssetService) listAccessScope(ctx context.Context, tenantID, actingUserID string, isAdmin bool) (assetdom.AccessScope, error) {
	if isAdmin || actingUserID == "" {
		return assetdom.AccessScope{}, nil
	}
	userID, err := shared.IDFromString(actingUserID)
	if err != nil {
		return assetdom.AccessScope{}, fmt.Errorf("%w: invalid acting user id", shared.ErrForbidden)
	}
	if full, ferr := s.fullDataCaller(ctx, tenantID, actingUserID); ferr != nil {
		return assetdom.AccessScope{}, ferr
	} else if full {
		return assetdom.AccessScope{}, nil
	}
	return assetdom.AccessScope{DataScopeUserID: &userID}, nil
}

// GetPropertyFacets returns distinct property keys and values for faceted
// filtering, counted only over the assets the acting user may list.
func (s *AssetService) GetPropertyFacets(ctx context.Context, tenantID, actingUserID string, isAdmin bool, types []string, subType string) ([]assetdom.PropertyFacet, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	access, err := s.listAccessScope(ctx, tenantID, actingUserID, isAdmin)
	if err != nil {
		return nil, err
	}
	return s.repo.GetPropertyFacets(ctx, parsedTenantID, access, types, subType)
}

// GetInventoryOverview returns the inventory overview counts, over the
// assets the acting user may list only.
func (s *AssetService) GetInventoryOverview(ctx context.Context, tenantID, actingUserID string, isAdmin bool) ([]assetdom.InventoryOverviewRow, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	access, err := s.listAccessScope(ctx, tenantID, actingUserID, isAdmin)
	if err != nil {
		return nil, err
	}
	return s.repo.GetInventoryOverview(ctx, parsedTenantID, access)
}

// GetAssetStats returns aggregated asset statistics using SQL aggregation,
// counted only over the assets the acting user may list.
// Filters: types (asset_type ANY), tags (overlap, matches List semantics).
func (s *AssetService) GetAssetStats(ctx context.Context, tenantID, actingUserID string, isAdmin bool, types []string, tags []string, subType string, countByFields ...string) (*assetdom.AggregateStats, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	access, err := s.listAccessScope(ctx, tenantID, actingUserID, isAdmin)
	if err != nil {
		return nil, err
	}
	return s.repo.GetAggregateStats(ctx, parsedTenantID, access, types, tags, subType, countByFields...)
}

// ListTags returns distinct tags across all assets for a tenant.
// Supports prefix filtering for autocomplete.
func (s *AssetService) ListTags(ctx context.Context, tenantID string, prefix string, types []string, limit int) ([]string, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	if limit <= 0 || limit > 100 {
		limit = 50
	}

	// Sanitize prefix: trim and limit length to prevent abuse
	prefix = strings.TrimSpace(prefix)
	if len(prefix) > 50 {
		prefix = prefix[:50]
	}

	return s.repo.ListDistinctTags(ctx, parsedTenantID, prefix, types, limit)
}

// ActivateAsset activates an asset.
// Security: Requires tenantID to prevent cross-tenant activation.
func (s *AssetService) ActivateAsset(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	oldStatus := a.Status().String()
	a.Activate()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to activate asset: %w", err)
	}

	s.recordStateChange(ctx, assetdom.RecordFieldChange(parsedTenantID, parsedID, assetdom.StateChangeStatusChanged, "status", oldStatus, a.Status().String(), assetdom.ChangeSourceManual, nil))
	s.logger.Info("asset activated", "id", assetID)
	return a, nil
}

// DeactivateAsset deactivates an asset.
// Security: Requires tenantID to prevent cross-tenant deactivation.
func (s *AssetService) DeactivateAsset(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	oldStatus := a.Status().String()
	a.Deactivate()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to deactivate asset: %w", err)
	}

	s.recordStateChange(ctx, assetdom.RecordFieldChange(parsedTenantID, parsedID, assetdom.StateChangeStatusChanged, "status", oldStatus, a.Status().String(), assetdom.ChangeSourceManual, nil))
	s.logger.Info("asset deactivated", "id", assetID)
	return a, nil
}

// ArchiveAsset archives an asset.
// Security: Requires tenantID to prevent cross-tenant archival.
func (s *AssetService) ArchiveAsset(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	oldStatus := a.Status().String()
	a.Archive()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to archive asset: %w", err)
	}

	s.recordStateChange(ctx, assetdom.RecordFieldChange(parsedTenantID, parsedID, assetdom.StateChangeStatusChanged, "status", oldStatus, a.Status().String(), assetdom.ChangeSourceManual, nil))
	s.logger.Info("asset archived", "id", assetID)
	return a, nil
}

// BulkUpdateAssetStatusInput represents input for bulk asset status update.
type BulkUpdateAssetStatusInput struct {
	AssetIDs []string
	Status   string // "active", "inactive", "archived"
}

// BulkAssetStatusResult represents the result of a bulk asset status operation.
type BulkAssetStatusResult struct {
	Updated int      `json:"updated"`
	Failed  int      `json:"failed"`
	Errors  []string `json:"errors,omitempty"`
}

// BulkUpdateAssetStatus atomically updates the status of multiple assets.
// Security: Requires tenantID to prevent cross-tenant status changes.
// Uses a single SQL UPDATE with IN clause for atomicity.
func (s *AssetService) BulkUpdateAssetStatus(ctx context.Context, tenantID string, input BulkUpdateAssetStatusInput) (*BulkAssetStatusResult, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	if len(input.AssetIDs) == 0 {
		return &BulkAssetStatusResult{}, nil
	}

	// Validate status
	parsedStatus, err := assetdom.ParseStatus(input.Status)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid status '%s', must be one of: active, inactive, archived", shared.ErrValidation, input.Status)
	}

	// Parse and validate all IDs first
	result := &BulkAssetStatusResult{}
	validIDs := make([]shared.ID, 0, len(input.AssetIDs))
	for _, idStr := range input.AssetIDs {
		parsedID, err := shared.IDFromString(idStr)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: invalid id format", idStr))
			continue
		}
		validIDs = append(validIDs, parsedID)
	}

	// Layer 2: drop assets outside the caller's data scope. They count as
	// failed, exactly like ids that do not exist.
	inScope, err := s.dataScope.FilterForCaller(ctx, parsedTenantID, validIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve data scope: %w", err)
	}
	scopedIDs := validIDs[:0]
	for _, id := range validIDs {
		if inScope(id) {
			scopedIDs = append(scopedIDs, id)
		} else {
			result.Failed++
		}
	}
	validIDs = scopedIDs

	if len(validIDs) == 0 {
		return result, nil
	}

	// Atomic bulk update - single SQL statement
	updated, err := s.repo.BulkUpdateStatus(ctx, parsedTenantID, validIDs, parsedStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to bulk update status: %w", err)
	}

	result.Updated = int(updated)
	// If fewer rows updated than requested, some IDs were not found
	if int(updated) < len(validIDs) {
		result.Failed += len(validIDs) - int(updated)
	}

	s.logger.Info("bulk asset status update completed",
		"status", input.Status,
		"updated", result.Updated,
		"failed", result.Failed)

	return result, nil
}

// CreateRepositoryAssetInput represents the input for creating a repository asset.
type CreateRepositoryAssetInput struct {
	// Basic info
	TenantID       string   `validate:"omitempty,uuid"`
	Name           string   `validate:"required,min=1,max=255"`
	Description    string   `validate:"max=1000"`
	Criticality    string   `validate:"required,criticality"`
	Scope          string   `validate:"omitempty,scope"`
	Exposure       string   `validate:"omitempty,exposure"`
	Tags           []string `validate:"max=20,dive,max=50"`
	Provider       string   `validate:"omitempty"`
	ExternalID     string   `validate:"omitempty,max=255"`
	Classification string   `validate:"omitempty"`
	// Repository extension fields
	RepoID          string           `validate:"omitempty,max=255"`
	FullName        string           `validate:"required,max=500"`
	SCMOrganization string           `validate:"omitempty,max=255"`
	CloneURL        string           `validate:"omitempty,url"`
	WebURL          string           `validate:"omitempty,url"`
	SSHURL          string           `validate:"omitempty,max=500"`
	DefaultBranch   string           `validate:"omitempty,max=100"`
	Visibility      string           `validate:"omitempty"`
	Language        string           `validate:"omitempty,max=50"`
	Languages       map[string]int64 `validate:"omitempty"`
	Topics          []string         `validate:"max=50,dive,max=100"`
	// Stats
	Stars      int `validate:"min=0"`
	Forks      int `validate:"min=0"`
	Watchers   int `validate:"min=0"`
	OpenIssues int `validate:"min=0"`
	SizeKB     int `validate:"min=0"`
	// Scan settings
	ScanEnabled  bool   `validate:"omitempty"`
	ScanSchedule string `validate:"omitempty,max=100"`
	// Timestamps from SCM (ISO 8601 format)
	RepoCreatedAt string `validate:"omitempty"`
	RepoUpdatedAt string `validate:"omitempty"`
	RepoPushedAt  string `validate:"omitempty"`
}

// CreateRepositoryAsset creates a new repository asset with its extension.
// If an existing asset matches (by name or fullName), it will be updated with SCM data.
func (s *AssetService) CreateRepositoryAsset(ctx context.Context, input CreateRepositoryAssetInput) (*assetdom.Asset, *assetdom.RepositoryExtension, error) {
	a, ext, _, err := s.CreateRepositoryAssetWithOutcome(ctx, input)
	return a, ext, err
}

// CreateRepositoryAssetWithOutcome is CreateRepositoryAsset that also says
// whether the request merged into an existing asset. As for CreateAsset, an
// existing asset outside the caller's data scope is a plain conflict, and a
// merge never changes the existing criticality.
func (s *AssetService) CreateRepositoryAssetWithOutcome(ctx context.Context, input CreateRepositoryAssetInput) (*assetdom.Asset, *assetdom.RepositoryExtension, CreateOutcome, error) {
	var none CreateOutcome
	if s.repoExtRepo == nil {
		return nil, nil, none, fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	s.logger.Info("creating repository asset", "name", input.Name, "fullName", input.FullName)

	criticality, err := assetdom.ParseCriticality(input.Criticality)
	if err != nil {
		return nil, nil, none, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	// Parse tenant ID early for searching
	var tenantID shared.ID
	if input.TenantID != "" {
		tenantID, err = shared.IDFromString(input.TenantID)
		if err != nil {
			return nil, nil, none, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
	}

	// Try to find existing asset that matches this repository
	// This handles the case where a sensor created the asset first
	existingAsset := s.findMatchingRepositoryAsset(ctx, tenantID, input)
	if existingAsset != nil {
		s.logger.Info("found existing asset, updating with SCM data",
			"asset_id", existingAsset.ID().String(),
			"existing_name", existingAsset.Name(),
			"new_fullName", input.FullName,
		)
		if s.dataScope.AssertAsset(ctx, tenantID, existingAsset.ID()) != nil {
			return nil, nil, none, errCreateConflict
		}
		a, ext, err := s.updateExistingRepositoryAsset(ctx, existingAsset, input)
		return a, ext, CreateOutcome{Merged: true}, err
	}

	// Check if asset with same name exists (strict check for new assets)
	exists, err := s.repo.ExistsByName(ctx, tenantID, input.Name)
	if err != nil {
		return nil, nil, none, fmt.Errorf("failed to check asset existence: %w", err)
	}
	if exists {
		return nil, nil, none, assetdom.AlreadyExistsError(input.Name)
	}

	// Create the base asset with Repository type
	a, err := assetdom.NewAsset(input.Name, assetdom.AssetTypeRepository, criticality)
	if err != nil {
		return nil, nil, none, err
	}

	// Set tenant ID if provided (already parsed above)
	if !tenantID.IsZero() {
		a.SetTenantID(tenantID)
	}

	// Set scope if provided
	if input.Scope != "" {
		scope, err := assetdom.ParseScope(input.Scope)
		if err != nil {
			return nil, nil, none, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		_ = a.UpdateScope(scope)
	}

	// Set exposure if provided
	if input.Exposure != "" {
		exposure, err := assetdom.ParseExposure(input.Exposure)
		if err != nil {
			return nil, nil, none, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		_ = a.UpdateExposure(exposure)
	}

	if input.Description != "" {
		a.UpdateDescription(input.Description)
	}
	for _, tag := range input.Tags {
		a.AddTag(tag)
	}

	// Set provider info if provided
	if input.Provider != "" {
		provider := assetdom.ParseProvider(input.Provider)
		a.SetProvider(provider)
		if input.ExternalID != "" {
			a.SetExternalID(input.ExternalID)
		}
	}

	// Set classification if provided
	if input.Classification != "" {
		classification := assetdom.ParseClassification(input.Classification)
		a.SetClassification(classification)
	}

	// Calculate initial risk score using tenant-specific config. A brand-new
	// repository asset has no BU / business-service membership yet, so effective
	// criticality == own criticality here; the business floor is applied on the
	// next persist (update/patch/recalc).
	a.CalculateRiskScoreWithConfig(s.getScoringConfig(ctx, tenantID))

	// Create the asset first
	if err := s.repo.Create(ctx, a); err != nil {
		return nil, nil, none, fmt.Errorf("failed to create asset: %w", err)
	}

	// Parse visibility
	visibility := assetdom.RepoVisibilityPrivate
	if input.Visibility != "" {
		visibility = assetdom.ParseRepoVisibility(input.Visibility)
	}

	// Create the repository extension
	repoExt, err := assetdom.NewRepositoryExtension(a.ID(), input.FullName, visibility)
	if err != nil {
		// Rollback: delete the asset if extension creation fails
		if deleteErr := s.repo.Delete(ctx, tenantID, a.ID(), nil); deleteErr != nil {
			s.logger.Error("rollback delete failed after extension creation error", "assetID", a.ID(), "error", deleteErr)
		}
		return nil, nil, none, fmt.Errorf("failed to create repository extension: %w", err)
	}

	// Apply optional repository extension fields
	applyRepoExtensionFields(repoExt, input)

	if err := s.repoExtRepo.Create(ctx, repoExt); err != nil {
		// Rollback: delete the asset if extension creation fails
		if deleteErr := s.repo.Delete(ctx, tenantID, a.ID(), nil); deleteErr != nil {
			s.logger.Error("rollback delete failed after repo extension save error", "assetID", a.ID(), "error", deleteErr)
		}
		return nil, nil, none, fmt.Errorf("failed to create repository extension: %w", err)
	}

	s.logger.Info("repository asset created", "id", a.ID().String(), "name", logger.SanitizeValue(a.Name()), "fullName", logger.SanitizeValue(input.FullName))
	return a, repoExt, none, nil
}

// applyRepoExtensionFields applies optional fields to a repository extension.
func applyRepoExtensionFields(repoExt *assetdom.RepositoryExtension, input CreateRepositoryAssetInput) {
	if input.RepoID != "" {
		repoExt.SetRepoID(input.RepoID)
	}
	if input.SCMOrganization != "" {
		repoExt.SetSCMOrganization(input.SCMOrganization)
	}
	if input.CloneURL != "" {
		repoExt.SetCloneURL(input.CloneURL)
	}
	if input.WebURL != "" {
		repoExt.SetWebURL(input.WebURL)
	}
	if input.SSHURL != "" {
		repoExt.SetSSHURL(input.SSHURL)
	}
	if input.DefaultBranch != "" {
		repoExt.SetDefaultBranch(input.DefaultBranch)
	}
	if input.Language != "" {
		repoExt.SetLanguage(input.Language)
	}
	if input.Languages != nil {
		repoExt.SetLanguages(input.Languages)
	}
	if len(input.Topics) > 0 {
		repoExt.SetTopics(input.Topics)
	}

	// Stats
	repoExt.UpdateStats(input.Stars, input.Forks, input.Watchers, input.OpenIssues, 0, input.SizeKB)

	// Scan settings
	if input.ScanEnabled {
		repoExt.EnableScan(input.ScanSchedule)
	} else {
		repoExt.DisableScan()
	}

	// Timestamps from SCM
	var repoCreatedAt, repoUpdatedAt, repoPushedAt *time.Time
	if input.RepoCreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, input.RepoCreatedAt); err == nil {
			repoCreatedAt = &t
		}
	}
	if input.RepoUpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, input.RepoUpdatedAt); err == nil {
			repoUpdatedAt = &t
		}
	}
	if input.RepoPushedAt != "" {
		if t, err := time.Parse(time.RFC3339, input.RepoPushedAt); err == nil {
			repoPushedAt = &t
		}
	}
	if repoCreatedAt != nil || repoUpdatedAt != nil || repoPushedAt != nil {
		repoExt.UpdateRepoTimestamps(repoCreatedAt, repoUpdatedAt, repoPushedAt)
	}
}

// GetRepositoryExtension retrieves the repository extension for an asset.
// Security: Requires tenantID to prevent cross-tenant data access.
func (s *AssetService) GetRepositoryExtension(ctx context.Context, tenantID, assetID string) (*assetdom.RepositoryExtension, error) {
	if s.repoExtRepo == nil {
		return nil, fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	// Verify asset exists and is a repository type
	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}
	if a.Type() != assetdom.AssetTypeRepository {
		return nil, shared.ErrNotFound
	}

	return s.repoExtRepo.GetByAssetID(ctx, parsedID)
}

// GetRepositoryExtensionsByAssetIDs retrieves repository extensions for multiple assets in a single query.
// Security: Caller must ensure all assetIDs belong to the specified tenant.
func (s *AssetService) GetRepositoryExtensionsByAssetIDs(ctx context.Context, assetIDs []shared.ID) (map[shared.ID]*assetdom.RepositoryExtension, error) {
	if s.repoExtRepo == nil {
		return make(map[shared.ID]*assetdom.RepositoryExtension), nil
	}

	return s.repoExtRepo.GetByAssetIDs(ctx, assetIDs)
}

// AssetDisplay is the label data other resources show for an asset.
type AssetDisplay struct {
	ID     string
	Name   string
	Type   string
	WebURL string // repository assets only; empty otherwise
}

// GetAssetDisplayInfo resolves the display label of many assets with two
// queries in total (assets by id, then repository extensions for the
// repository-typed ones), replacing one GetAssetWithRepository call — a full
// asset load with a per-asset finding aggregate, plus an extension lookup —
// per distinct asset on a findings page.
//
// Security: only assets of tenantID are returned (the tenant predicate is in
// the query); extensions are looked up only for ids that query returned.
// Malformed or unknown ids are absent from the result, matching the per-id
// path where a failed lookup leaves the asset unlabeled.
func (s *AssetService) GetAssetDisplayInfo(ctx context.Context, tenantID string, assetIDs []string) (map[string]AssetDisplay, error) {
	result := make(map[string]AssetDisplay, len(assetIDs))
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	seen := make(map[shared.ID]struct{}, len(assetIDs))
	ids := make([]shared.ID, 0, len(assetIDs))
	for _, raw := range assetIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return result, nil
	}

	infos, err := s.repo.GetDisplayInfoByIDs(ctx, parsedTenantID, ids)
	if err != nil {
		return nil, err
	}

	var repoIDs []shared.ID
	for id, info := range infos {
		result[id.String()] = AssetDisplay{ID: id.String(), Name: info.Name, Type: info.Type.String()}
		if info.Type == assetdom.AssetTypeRepository {
			repoIDs = append(repoIDs, id)
		}
	}

	if len(repoIDs) > 0 && s.repoExtRepo != nil {
		exts, err := s.repoExtRepo.GetByAssetIDs(ctx, repoIDs)
		if err != nil {
			// The label is still useful without the link; don't drop it.
			s.logger.Warn("failed to batch load repository extensions", "count", len(repoIDs), "error", err)
		} else {
			for id, ext := range exts {
				if d, ok := result[id.String()]; ok && ext != nil {
					d.WebURL = ext.WebURL()
					result[id.String()] = d
				}
			}
		}
	}

	return result, nil
}

// GetAssetWithRepository retrieves an asset with its repository extension.
// Security: Requires tenantID to prevent cross-tenant data access.
func (s *AssetService) GetAssetWithRepository(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, *assetdom.RepositoryExtension, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		// Return NotFound instead of Validation error - from user's perspective, resource doesn't exist
		return nil, nil, shared.ErrNotFound
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, nil, err
	}

	// Only fetch extension if it's a repository asset
	if a.Type() != assetdom.AssetTypeRepository || s.repoExtRepo == nil {
		return a, nil, nil
	}

	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, parsedID)
	if err != nil {
		// Only swallow "not found" errors - extension might not exist yet
		// Propagate other database errors
		if errors.Is(err, shared.ErrNotFound) {
			return a, nil, nil
		}
		s.logger.Error("database error getting repository extension", "assetID", assetID, "error", err)
		return nil, nil, fmt.Errorf("failed to get repository extension: %w", err)
	}

	return a, repoExt, nil
}

// UpdateRepositoryExtensionInput represents the input for updating a repository extension.
type UpdateRepositoryExtensionInput struct {
	RepoID               *string          `validate:"omitempty,max=255"`
	FullName             *string          `validate:"omitempty,max=500"`
	SCMOrganization      *string          `validate:"omitempty,max=255"`
	CloneURL             *string          `validate:"omitempty,url"`
	WebURL               *string          `validate:"omitempty,url"`
	SSHURL               *string          `validate:"omitempty,max=500"`
	DefaultBranch        *string          `validate:"omitempty,max=100"`
	Visibility           *string          `validate:"omitempty"`
	Language             *string          `validate:"omitempty,max=50"`
	Languages            map[string]int64 `validate:"omitempty"`
	Topics               []string         `validate:"omitempty,max=50,dive,max=100"`
	Stars                *int             `validate:"omitempty,min=0"`
	Forks                *int             `validate:"omitempty,min=0"`
	Watchers             *int             `validate:"omitempty,min=0"`
	OpenIssues           *int             `validate:"omitempty,min=0"`
	ContributorsCount    *int             `validate:"omitempty,min=0"`
	SizeKB               *int             `validate:"omitempty,min=0"`
	BranchCount          *int             `validate:"omitempty,min=0"`
	ProtectedBranchCount *int             `validate:"omitempty,min=0"`
	ComponentCount       *int             `validate:"omitempty,min=0"`
}

// UpdateRepositoryExtension updates the repository extension for an asset.
// Security: Requires tenantID to prevent cross-tenant data modification.
func (s *AssetService) UpdateRepositoryExtension(ctx context.Context, tenantID, assetID string, input UpdateRepositoryExtensionInput) (*assetdom.RepositoryExtension, error) {
	if s.repoExtRepo == nil {
		return nil, fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// Verify asset exists and is a repository type
	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}
	if a.Type() != assetdom.AssetTypeRepository {
		return nil, shared.ErrNotFound
	}

	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if input.RepoID != nil {
		repoExt.SetRepoID(*input.RepoID)
	}
	if input.FullName != nil {
		repoExt.SetFullName(*input.FullName)
	}
	if input.SCMOrganization != nil {
		repoExt.SetSCMOrganization(*input.SCMOrganization)
	}
	if input.CloneURL != nil {
		repoExt.SetCloneURL(*input.CloneURL)
	}
	if input.WebURL != nil {
		repoExt.SetWebURL(*input.WebURL)
	}
	if input.SSHURL != nil {
		repoExt.SetSSHURL(*input.SSHURL)
	}
	if input.DefaultBranch != nil {
		repoExt.SetDefaultBranch(*input.DefaultBranch)
	}
	if input.Visibility != nil {
		repoExt.SetVisibility(assetdom.ParseRepoVisibility(*input.Visibility))
	}
	if input.Language != nil {
		repoExt.SetLanguage(*input.Language)
	}
	if input.Languages != nil {
		repoExt.SetLanguages(input.Languages)
	}
	if input.Topics != nil {
		repoExt.SetTopics(input.Topics)
	}
	if input.Stars != nil {
		repoExt.SetStars(*input.Stars)
	}
	if input.Forks != nil {
		repoExt.SetForks(*input.Forks)
	}
	if input.Watchers != nil {
		repoExt.SetWatchers(*input.Watchers)
	}
	if input.OpenIssues != nil {
		repoExt.SetOpenIssues(*input.OpenIssues)
	}
	if input.ContributorsCount != nil {
		repoExt.SetContributorsCount(*input.ContributorsCount)
	}
	if input.SizeKB != nil {
		repoExt.SetSizeKB(*input.SizeKB)
	}
	if input.BranchCount != nil {
		repoExt.SetBranchCount(*input.BranchCount)
	}
	if input.ProtectedBranchCount != nil {
		repoExt.SetProtectedBranchCount(*input.ProtectedBranchCount)
	}
	if input.ComponentCount != nil {
		repoExt.SetComponentCount(*input.ComponentCount)
	}

	if err := s.repoExtRepo.Update(ctx, repoExt); err != nil {
		return nil, fmt.Errorf("failed to update repository extension: %w", err)
	}

	s.logger.Info("repository extension updated", "assetID", logger.SanitizeValue(assetID))
	return repoExt, nil
}

// RecordRepositoryScan records a scan completion for a repository.
func (s *AssetService) RecordRepositoryScan(ctx context.Context, assetID string) error {
	if s.repoExtRepo == nil {
		return fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, parsedID)
	if err != nil {
		return err
	}

	repoExt.RecordScan()

	if err := s.repoExtRepo.Update(ctx, repoExt); err != nil {
		return fmt.Errorf("failed to record repository scan: %w", err)
	}

	s.logger.Info("repository scan recorded", "assetID", assetID)
	return nil
}

// findMatchingRepositoryAsset tries to find an existing asset that matches the repository.
// This handles cases where a sensor created an asset before SCM sync.
func (s *AssetService) findMatchingRepositoryAsset(ctx context.Context, tenantID shared.ID, input CreateRepositoryAssetInput) *assetdom.Asset {
	// Extract repo name from FullName (e.g., "sdk" from "openctemio/sdk")
	repoName := input.Name
	if input.FullName != "" {
		parts := strings.Split(input.FullName, "/")
		repoName = parts[len(parts)-1]
	}

	// Parse provider
	provider := assetdom.ProviderManual
	if input.Provider != "" {
		provider = assetdom.ParseProvider(input.Provider)
	}

	// 1. Try to find by external_id matching FullName (e.g., "openctemio/sdk")
	if input.FullName != "" && !tenantID.IsZero() {
		existing, err := s.repo.GetByExternalID(ctx, tenantID, provider, input.FullName)
		if err == nil && existing != nil {
			return existing
		}
	}

	// 2. Try to find by name matching the repo name
	// This handles sensor-created assets with names like "github.com/openctemio/sdk-go"
	if !tenantID.IsZero() {
		existing, err := s.repo.GetByName(ctx, tenantID, repoName)
		if err == nil && existing != nil && existing.Type() == assetdom.AssetTypeRepository {
			return existing
		}
	}

	// 3. Try to find by exact name match
	if !tenantID.IsZero() {
		existing, err := s.repo.GetByName(ctx, tenantID, input.Name)
		if err == nil && existing != nil && existing.Type() == assetdom.AssetTypeRepository {
			return existing
		}
	}

	// 4. Try to find by external_id containing the repo name
	// This handles sensor-created assets with external_id like "openctemio/openctemio/sdk"
	if input.FullName != "" && !tenantID.IsZero() {
		existing, err := s.repo.GetByExternalID(ctx, tenantID, provider, repoName)
		if err == nil && existing != nil {
			return existing
		}
	}

	// 5. Try to find repository asset by full name (org/repo pattern) - MORE PRECISE
	// This handles sensor-created assets like "github.com-xxx/openctemio/sdk"
	// matching FullName "openctemio/sdk"
	if input.FullName != "" && !tenantID.IsZero() {
		existing, err := s.repo.FindRepositoryByFullName(ctx, tenantID, input.FullName)
		if err == nil && existing != nil {
			s.logger.Debug("found existing asset by full name pattern",
				"asset_id", existing.ID().String(),
				"existing_name", existing.Name(),
				"full_name", input.FullName,
			)
			return existing
		}
	}

	// 6. Try to find repository asset whose name ends with the repo name - LESS PRECISE
	// This is a fallback and may match incorrectly if there are multiple repos with same name
	// Only use this if no other match was found
	// NOTE: This could match github.com/a/repo with github.com/b/repo incorrectly!
	// if repoName != "" && !tenantID.IsZero() {
	// 	existing, err := s.repo.FindRepositoryByRepoName(ctx, tenantID, repoName)
	// 	if err == nil && existing != nil {
	// 		s.logger.Debug("found existing asset by repo name suffix",
	// 			"asset_id", existing.ID().String(),
	// 			"existing_name", existing.Name(),
	// 			"repo_name", repoName,
	// 		)
	// 		return existing
	// 	}
	// }

	return nil
}

// updateExistingRepositoryAsset updates an existing asset with new SCM data.
func (s *AssetService) updateExistingRepositoryAsset(
	ctx context.Context,
	existingAsset *assetdom.Asset,
	input CreateRepositoryAssetInput,
) (*assetdom.Asset, *assetdom.RepositoryExtension, error) {
	// Update asset fields with SCM data
	// Only update name if the existing name looks like a sensor-generated name
	existingName := existingAsset.Name()
	if strings.Contains(existingName, "github.com-") ||
		strings.Contains(existingName, "gitlab.com-") ||
		strings.Contains(existingName, "bitbucket.org-") {
		// Update to the clean name from SCM
		if err := existingAsset.UpdateName(input.Name); err != nil {
			s.logger.Warn("failed to update asset name", "error", err)
		}
	}

	// The criticality is left alone: a create is not an edit of a deliberate
	// field (change it with an update).

	// Update description if provided
	if input.Description != "" {
		existingAsset.UpdateDescription(input.Description)
	}

	// Set scope if provided
	if input.Scope != "" {
		scope, _ := assetdom.ParseScope(input.Scope)
		_ = existingAsset.UpdateScope(scope)
	}

	// Set exposure if provided
	if input.Exposure != "" {
		exposure, _ := assetdom.ParseExposure(input.Exposure)
		_ = existingAsset.UpdateExposure(exposure)
	}

	// Update provider info from SCM
	if input.Provider != "" {
		provider := assetdom.ParseProvider(input.Provider)
		existingAsset.SetProvider(provider)
	}
	if input.ExternalID != "" {
		existingAsset.SetExternalID(input.ExternalID)
	} else if input.FullName != "" {
		// Use FullName as external_id for matching
		existingAsset.SetExternalID(input.FullName)
	}

	// Update classification if provided
	if input.Classification != "" {
		classification := assetdom.ParseClassification(input.Classification)
		existingAsset.SetClassification(classification)
	}

	// Add new tags
	for _, tag := range input.Tags {
		existingAsset.AddTag(tag)
	}

	// Recalculate risk score using the asset's effective (BU/service-aligned)
	// criticality. Nil-safe fallback to own criticality.
	s.scoreAsset(ctx, existingAsset.TenantID(), existingAsset)

	// Mark as synced
	existingAsset.MarkSynced()

	// Update the asset
	if err := s.repo.Update(ctx, existingAsset); err != nil {
		return nil, nil, fmt.Errorf("failed to update existing asset: %w", err)
	}

	// Try to get existing repository extension, or create new one
	var repoExt *assetdom.RepositoryExtension
	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, existingAsset.ID())
	if err != nil || repoExt == nil {
		// Create new repository extension
		visibility := assetdom.RepoVisibilityPrivate
		if input.Visibility != "" {
			visibility = assetdom.ParseRepoVisibility(input.Visibility)
		}

		repoExt, err = assetdom.NewRepositoryExtension(existingAsset.ID(), input.FullName, visibility)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create repository extension: %w", err)
		}

		applyRepoExtensionFields(repoExt, input)

		if err := s.repoExtRepo.Create(ctx, repoExt); err != nil {
			return nil, nil, fmt.Errorf("failed to create repository extension: %w", err)
		}
	} else {
		// Update existing repository extension
		if input.FullName != "" {
			repoExt.SetFullName(input.FullName)
		}
		if input.Visibility != "" {
			repoExt.SetVisibility(assetdom.ParseRepoVisibility(input.Visibility))
		}

		applyRepoExtensionFields(repoExt, input)

		if err := s.repoExtRepo.Update(ctx, repoExt); err != nil {
			return nil, nil, fmt.Errorf("failed to update repository extension: %w", err)
		}
	}

	s.logger.Info("updated existing repository asset with SCM data",
		"asset_id", existingAsset.ID().String(),
		"name", logger.SanitizeValue(existingAsset.Name()),
		"fullName", input.FullName,
	)

	return existingAsset, repoExt, nil
}

// RecalculateAllRiskScores recalculates risk scores for all assets in a tenant
// using the current scoring configuration. Processes assets in batches.
//
// It scores each asset on its EFFECTIVE (business-aligned) criticality —
// MAX(own, its BU, the services it powers) — so this is the mechanism that heals
// scores gone stale after a business-unit / business-service criticality change
// (member assets are not otherwise re-scored until their next individual
// persist). Trigger it from the scoring-settings-changed path or an admin
// action. Nil-safe: with no business-context lookup wired it scores on own
// criticality, unchanged.
func (s *AssetService) RecalculateAllRiskScores(ctx context.Context, tenantID shared.ID) (int, error) {
	tid := tenantID.String()

	// Acquire distributed lock to prevent concurrent recalculations
	if s.redisClient != nil {
		lockKey := recalcLockKeyPrefix + tid
		acquired, err := s.redisClient.SetNX(ctx, lockKey, "1", recalcLockTTL)
		switch {
		case err != nil:
			s.logger.Warn("failed to acquire recalc lock, proceeding anyway", "tenant_id", tid, "error", err)
		case !acquired:
			return 0, fmt.Errorf("%w: risk score recalculation already in progress", shared.ErrConflict)
		default:
			defer func() {
				_ = s.redisClient.Client().Del(ctx, lockKey)
			}()
		}
	}

	// Invalidate scoring cache before starting
	s.InvalidateScoringConfigCache(tenantID)

	config := s.getScoringConfig(ctx, tenantID)
	engine := assetdom.NewRiskScoringEngine(*config)

	// Check total asset count
	filter := assetdom.NewFilter().WithTenantID(tid)
	countPage := pagination.New(1, 1)
	countResult, err := s.repo.List(ctx, filter, assetdom.NewListOptions(), countPage)
	if err != nil {
		return 0, fmt.Errorf("failed to count assets: %w", err)
	}
	if countResult.Total > maxRecalcAssets {
		return 0, fmt.Errorf("%w: too many assets (%d), max %d", shared.ErrValidation, countResult.Total, maxRecalcAssets)
	}

	const batchSize = 500
	totalUpdated := 0
	pageNum := 1

	for {
		page := pagination.New(pageNum, batchSize)

		result, err := s.repo.List(ctx, filter, assetdom.NewListOptions(), page)
		if err != nil {
			return totalUpdated, fmt.Errorf("failed to list assets for recalculation: %w", err)
		}

		if len(result.Data) == 0 {
			break
		}

		// Batch-resolve each asset's effective (BU/service-aligned) criticality in
		// ONE lookup per page, then recalc scores in memory. This is also the path
		// that heals stale scores after a BU/service criticality change (see
		// RecalculateAllRiskScores doc). Nil-safe: with no lookup wired every asset
		// maps to its own criticality and scores are unchanged.
		effByID := s.effectiveCriticalityMap(ctx, tenantID, result.Data)
		changed := make([]*assetdom.Asset, 0, len(result.Data))
		for _, a := range result.Data {
			eff := effByID[a.ID()]
			oldScore := a.RiskScore()
			newScore := engine.CalculateScoreWithCriticality(a, eff)
			if oldScore != newScore {
				a.CalculateRiskScoreWithConfigAndCriticality(config, eff)
				changed = append(changed, a)
			}
		}

		// Batch update only changed assets
		if len(changed) > 0 {
			if err := s.repo.BatchUpdateRiskScores(ctx, tenantID, changed); err != nil {
				return totalUpdated, fmt.Errorf("failed to batch update risk scores: %w", err)
			}
			totalUpdated += len(changed)
		}

		if len(result.Data) < batchSize {
			break
		}
		pageNum++
	}

	s.logger.Info("recalculated risk scores", "tenant_id", tid, "updated", totalUpdated)
	return totalUpdated, nil
}

// PreviewRiskScoreChanges previews how a scoring config change would affect assets.
// Uses stratified sampling: top 20 + bottom 20 + random 60 assets.
// Returns preview items and total asset count for context.
func (s *AssetService) PreviewRiskScoreChanges(ctx context.Context, tenantID shared.ID, newConfig *assetdom.RiskScoringConfig) ([]RiskScorePreviewItem, int64, error) {
	tid := tenantID.String()
	engine := assetdom.NewRiskScoringEngine(*newConfig)

	// Get a sample of assets — top risk, bottom risk, and a middle page
	filter := assetdom.NewFilter().WithTenantID(tid)

	// Get total count for context
	totalCount, err := s.repo.Count(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count assets: %w", err)
	}
	allowedSort := assetdom.AllowedSortFields()
	sortDesc := pagination.NewSortOption(allowedSort).Parse("-risk_score")
	sortAsc := pagination.NewSortOption(allowedSort).Parse("risk_score")

	topPage := pagination.New(1, 20)
	bottomPage := pagination.New(1, 20)
	middlePage := pagination.New(1, 60)

	topResult, err := s.repo.List(ctx, filter, assetdom.NewListOptions().WithSort(sortDesc), topPage)
	if err != nil {
		return nil, totalCount, fmt.Errorf("failed to get top-risk assets: %w", err)
	}

	bottomResult, err := s.repo.List(ctx, filter, assetdom.NewListOptions().WithSort(sortAsc), bottomPage)
	if err != nil {
		return nil, totalCount, fmt.Errorf("failed to get bottom-risk assets: %w", err)
	}

	middleResult, err := s.repo.List(ctx, filter, assetdom.NewListOptions(), middlePage)
	if err != nil {
		return nil, totalCount, fmt.Errorf("failed to get middle assets: %w", err)
	}

	// Deduplicate
	seen := make(map[string]bool)
	items := make([]RiskScorePreviewItem, 0, 100)

	addItems := func(assets []*assetdom.Asset) {
		for _, a := range assets {
			id := a.ID().String()
			if seen[id] {
				continue
			}
			seen[id] = true
			newScore := engine.CalculateScore(a)
			items = append(items, RiskScorePreviewItem{
				AssetID:      id,
				AssetName:    a.Name(),
				AssetType:    string(a.Type()),
				CurrentScore: a.RiskScore(),
				NewScore:     newScore,
				Delta:        newScore - a.RiskScore(),
			})
		}
	}

	addItems(topResult.Data)
	addItems(bottomResult.Data)
	addItems(middleResult.Data)

	return items, totalCount, nil
}

// RiskScorePreviewItem represents how an asset's risk score would change.
type RiskScorePreviewItem struct {
	AssetID      string `json:"asset_id"`
	AssetName    string `json:"asset_name"`
	AssetType    string `json:"asset_type"`
	CurrentScore int    `json:"current_score"`
	NewScore     int    `json:"new_score"`
	Delta        int    `json:"delta"`
}

// tagsEqual compares two string slices for equality (order-insensitive).
func tagsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, t := range a {
		set[t] = struct{}{}
	}
	for _, t := range b {
		if _, ok := set[t]; !ok {
			return false
		}
	}
	return true
}
