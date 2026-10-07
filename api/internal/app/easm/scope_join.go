package easm

// Discovered names that a declared scope entry covers join the inventory
// (RFC-054 §4.3, owner decision S4 as refined 2026-10-07).
//
// A tenant that declares a permanent scope target (`x`, `*.x`) or a
// root-domain seed claims the names under it as its own, with step-up and
// approval. So a discovered name such an entry covers gets the strong rule
// matches_scope_target and the attribution engine confirms it, without the
// review queue:
//
//   - names only from domain entries and seeds; an IP address only from an
//     IP, range or CIDR entry that contains it (a name never lends its
//     address anything); a service follows its host;
//   - expiring (one-off) entries authorize scanning only and never confirm;
//   - an active exclusion, a tombstone, or a rejected name at or above the
//     name always wins;
//   - a person's decision is never touched (SaveAutomatic skips decided rows
//     and attribution.Merge never overrides one).
//
// Confirmation is not ownership proof: platform sensors still need a
// verified domain (RFC-054 §8.1).
//
// Every lookup and write is tenant-scoped; any lookup error stops the join
// for that call (nothing is confirmed on a partial view).

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TechniqueScopeTarget is the technique of matches_scope_target evidence.
const TechniqueScopeTarget = "scope_target"

// JoinItem is one asset the join looks at.
type JoinItem struct {
	ID      string
	Name    string
	Type    asset.AssetType
	SubType string
}

// ScopeJoinTargets lists the tenant's active scope targets (*scope.Service).
type ScopeJoinTargets interface {
	ListActiveTargets(ctx context.Context, tenantID string) ([]*scopedom.Target, error)
}

// ScopeJoinSeeds lists the tenant's root-domain seeds
// (*postgres.EASMSeedRepository).
type ScopeJoinSeeds interface {
	RootDomainSeedNames(ctx context.Context, tenantID shared.ID) ([]string, error)
}

// ScopeJoinExclusions reports which candidates an active exclusion matches,
// failing closed (*scope.Service).
type ScopeJoinExclusions interface {
	ExcludedTargets(ctx context.Context, tenantID string, candidates []scope.ExclusionCandidate) (map[shared.ID]bool, error)
}

// ScopeJoinStore reads and writes attribution (*postgres.AttributionRepository).
type ScopeJoinStore interface {
	ActiveGateRecords
	UpsertEvidence(ctx context.Context, tenantID shared.ID, ev []attribution.Evidence) error
	FiredRules(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string][]attribution.Rule, error)
	SaveAutomatic(ctx context.Context, tenantID shared.ID, assetID string, d attribution.Decision) error
	// PendingAutomatic lists up to limit of the tenant's assets whose record
	// is needs_review or candidate and was not decided by a person.
	PendingAutomatic(ctx context.Context, tenantID shared.ID, limit int) ([]JoinItem, error)
	// TenantsWithPendingAutomatic lists the tenants that have such records.
	TenantsWithPendingAutomatic(ctx context.Context) ([]shared.ID, error)
}

// ScopeJoinSettings reads the tenant's scope settings (*tenant.TenantService):
// auto_join_discovered off sends every name to review (RFC-054 §6.3).
type ScopeJoinSettings interface {
	GetScopeSettings(ctx context.Context, tenantID string) (*tenant.ScopeSettings, error)
}

// ScopeJoinAudit records the system decision.
type ScopeJoinAudit interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// ScopeJoin applies matches_scope_target.
type ScopeJoin struct {
	targets    ScopeJoinTargets
	seeds      ScopeJoinSeeds
	exclusions ScopeJoinExclusions
	store      ScopeJoinStore
	assets     ActiveGateAssets
	settings   ScopeJoinSettings
	audit      ScopeJoinAudit
	log        *logger.Logger
}

// NewScopeJoin wires the join. Every source is required; with a nil one the
// join confirms nothing and reports an error.
func NewScopeJoin(targets ScopeJoinTargets, seeds ScopeJoinSeeds, exclusions ScopeJoinExclusions,
	store ScopeJoinStore, assets ActiveGateAssets, log *logger.Logger,
) *ScopeJoin {
	if log == nil {
		log = logger.NewNop()
	}
	return &ScopeJoin{targets: targets, seeds: seeds, exclusions: exclusions, store: store, assets: assets,
		log: log.With("component", "scope-join")}
}

// SetSettings wires the tenant's auto-join setting (nil: on).
func (j *ScopeJoin) SetSettings(s ScopeJoinSettings) { j.settings = s }

// SetAudit wires the audit log.
func (j *ScopeJoin) SetAudit(a ScopeJoinAudit) { j.audit = a }

func (j *ScopeJoin) ready() error {
	if j == nil || j.targets == nil || j.seeds == nil || j.exclusions == nil || j.store == nil || j.assets == nil {
		return fmt.Errorf("scope join is not configured")
	}
	return nil
}

// joinRoots is what may confirm: permanent active scope targets and seeds.
type joinRoots struct {
	domainTargets []*scopedom.Target
	ipTargets     []*scopedom.Target
	seeds         []string
}

func (j *ScopeJoin) loadRoots(ctx context.Context, tenantID shared.ID) (*joinRoots, error) {
	targets, err := j.targets.ListActiveTargets(ctx, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list scope targets: %w", err)
	}
	seeds, err := j.seeds.RootDomainSeedNames(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list root-domain seeds: %w", err)
	}
	r := &joinRoots{}
	for _, t := range targets {
		if t == nil || !t.IsActive() || !permanent(t) {
			continue
		}
		switch t.TargetType() {
		case scopedom.TargetTypeDomain, scopedom.TargetTypeSubdomain:
			r.domainTargets = append(r.domainTargets, t)
		case scopedom.TargetTypeIPAddress, scopedom.TargetTypeIPRange, scopedom.TargetTypeCIDR:
			r.ipTargets = append(r.ipTargets, t)
		}
	}
	for _, s := range seeds {
		if s = normalizeHost(s); s != "" {
			r.seeds = append(r.seeds, s)
		}
	}
	return r, nil
}

// permanent reports whether a scope target confirms inventory: one-off
// (expiring) entries authorize scanning only.
func permanent(t *scopedom.Target) bool {
	if t == nil {
		return false
	}
	if e, ok := any(t).(interface{ ExpiresAt() *time.Time }); ok && e.ExpiresAt() != nil {
		return false
	}
	return true
}

// match returns the source that covers the item ("" for none).
func (r *joinRoots) match(it JoinItem) string {
	if ip := itemAddress(it); ip != "" {
		for _, t := range r.ipTargets {
			if t.Matches(ip) {
				return "scope_target:" + t.ID().String()
			}
		}
		return ""
	}
	host := dnsHost(it.Name)
	if host == "" {
		return ""
	}
	for _, t := range r.domainTargets {
		if t.Matches(host) {
			return "scope_target:" + t.ID().String()
		}
	}
	for _, s := range r.seeds {
		if host == s || strings.HasSuffix(host, "."+s) {
			return "easm_seed:" + s
		}
	}
	return ""
}

// itemAddress is the item's IP address when the item is an address (or a
// service on one); "" for names.
func itemAddress(it JoinItem) string {
	if a, err := netip.ParseAddr(asset.HostOf(it.Name)); err == nil {
		return a.Unmap().String()
	}
	return ""
}

// Covered returns, for the items a permanent scope entry or seed covers and
// nothing keeps out (exclusion, tombstone, rejected name), the evidence
// source that covers each (asset id -> "scope_target:<id>" or
// "easm_seed:<root>"). With auto-join off it returns nothing.
func (j *ScopeJoin) Covered(ctx context.Context, tenantID shared.ID, items []JoinItem) (map[string]string, error) {
	if err := j.ready(); err != nil {
		return nil, err
	}
	out := map[string]string{}
	if len(items) == 0 {
		return out, nil
	}
	if j.settings != nil {
		st, err := j.settings.GetScopeSettings(ctx, tenantID.String())
		if err != nil {
			return nil, fmt.Errorf("read scope settings: %w", err)
		}
		if st != nil && st.AutoJoinDisabled {
			return out, nil
		}
	}
	roots, err := j.loadRoots(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	matched := map[string]string{}
	cands := make([]scope.ExclusionCandidate, 0, len(items))
	byCand := map[shared.ID]string{}
	hosts := map[string]string{}
	for _, it := range items {
		src := roots.match(it)
		if src == "" {
			continue
		}
		id, err := shared.IDFromString(it.ID)
		if err != nil {
			continue
		}
		matched[it.ID] = src
		cands = append(cands, scope.ExclusionCandidate{ID: id, Values: []string{it.Name}})
		byCand[id] = it.ID
		if h := dnsHost(it.Name); h != "" {
			hosts[it.ID] = h
		}
	}
	if len(matched) == 0 {
		return out, nil
	}
	excluded, err := j.exclusions.ExcludedTargets(ctx, tenantID.String(), cands)
	if err != nil {
		return nil, fmt.Errorf("check scope exclusions: %w", err)
	}
	gate := &ActiveGate{records: j.store, assets: j.assets}
	rejected, err := gate.rejectedNames(ctx, tenantID, hostValues(hosts))
	if err != nil {
		return nil, err
	}
	for cid, assetID := range byCand {
		if excluded[cid] {
			continue
		}
		if h, ok := hosts[assetID]; ok && underAny(h, rejected) {
			continue
		}
		out[assetID] = matched[assetID]
	}
	return out, nil
}

// Evidence is the matches_scope_target evidence for the covered items.
func (j *ScopeJoin) Evidence(ctx context.Context, tenantID shared.ID, items []JoinItem) ([]attribution.Evidence, error) {
	covered, err := j.Covered(ctx, tenantID, items)
	if err != nil {
		return nil, err
	}
	return joinEvidence(covered), nil
}

// JoinEvidence is Evidence for names given as asset id -> name (Certificate
// Transparency promotion: every name is a subdomain).
func (j *ScopeJoin) JoinEvidence(ctx context.Context, tenantID shared.ID, names map[string]string) ([]attribution.Evidence, error) {
	items := make([]JoinItem, 0, len(names))
	for id, n := range names {
		items = append(items, JoinItem{ID: id, Name: n, Type: asset.AssetTypeSubdomain})
	}
	return j.Evidence(ctx, tenantID, items)
}

func joinEvidence(covered map[string]string) []attribution.Evidence {
	w, _, _ := attribution.Weight(attribution.RuleMatchesScopeTarget)
	ids := make([]string, 0, len(covered))
	for id := range covered {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]attribution.Evidence, 0, len(ids))
	for _, id := range ids {
		src := covered[id]
		out = append(out, attribution.Evidence{
			AssetID: id, Rule: attribution.RuleMatchesScopeTarget, Technique: TechniqueScopeTarget,
			Source: src, Weight: w, Observed: map[string]any{"covered_by": src},
		})
	}
	return out
}

// maxReevaluate bounds one tenant's re-evaluation per call.
const maxReevaluate = 5000

// Reevaluate confirms the tenant's pending automatic records (needs_review,
// candidate) that a permanent scope entry or seed now covers. It is the
// backfill when the rule ships and runs again whenever an entry becomes
// active. Idempotent: evidence is upserted per (asset, rule, source), and a
// confirmed record is not pending any more. It returns the confirmed names.
func (j *ScopeJoin) Reevaluate(ctx context.Context, tenantID shared.ID) ([]string, error) {
	if err := j.ready(); err != nil {
		return nil, err
	}
	pending, err := j.store.PendingAutomatic(ctx, tenantID, maxReevaluate)
	if err != nil {
		return nil, fmt.Errorf("list pending attribution: %w", err)
	}
	if len(pending) == 0 {
		return nil, nil
	}
	covered, err := j.Covered(ctx, tenantID, pending)
	if err != nil {
		return nil, err
	}
	if len(covered) == 0 {
		return nil, nil
	}
	if err := j.store.UpsertEvidence(ctx, tenantID, joinEvidence(covered)); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(covered))
	for id := range covered {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fired, err := j.store.FiredRules(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	records, err := j.store.Records(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	nameOf := make(map[string]string, len(pending))
	for _, it := range pending {
		nameOf[it.ID] = it.Name
	}
	var confirmed []string
	for _, id := range ids {
		rec, has := records[id]
		if !has || rec.HumanDecided {
			continue
		}
		dec, err := attribution.Evaluate(fired[id])
		if err != nil {
			return confirmed, err
		}
		merged := attribution.Merge(&rec, dec)
		if err := j.store.SaveAutomatic(ctx, tenantID, id, merged); err != nil {
			return confirmed, err
		}
		if merged.State == attribution.StateConfirmed && rec.State != attribution.StateConfirmed {
			confirmed = append(confirmed, nameOf[id])
		}
	}
	j.auditConfirmed(ctx, tenantID, confirmed)
	return confirmed, nil
}

// maxAuditedNames bounds the names one audit event lists.
const maxAuditedNames = 50

func (j *ScopeJoin) auditConfirmed(ctx context.Context, tenantID shared.ID, names []string) {
	if len(names) == 0 {
		return
	}
	j.log.Info("scope join confirmed pending names", "tenant_id", tenantID.String(), "count", len(names))
	if j.audit == nil {
		return
	}
	listed := names
	if len(listed) > maxAuditedNames {
		listed = listed[:maxAuditedNames]
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionAssetAttributionAutoConfirmed, auditdom.ResourceTypeTenant, tenantID.String()).
		WithMessage(fmt.Sprintf("%d discovered name(s) confirmed: a scope target or seed of the organization covers them", len(names))).
		WithMetadata("rule", string(attribution.RuleMatchesScopeTarget)).
		WithMetadata("count", len(names)).
		WithMetadata("names", listed).
		WithMetadata("actor", "system").
		WithSeverity(auditdom.SeverityMedium)
	if err := j.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String()}, event); err != nil {
		j.log.Warn("scope join audit failed", "error", logger.SanitizeError(err))
	}
}

// ReevaluateAll runs Reevaluate for every tenant with pending automatic
// records (the backfill). One tenant's failure is logged and does not stop
// the others.
func (j *ScopeJoin) ReevaluateAll(ctx context.Context) (int, error) {
	if err := j.ready(); err != nil {
		return 0, err
	}
	tenants, err := j.store.TenantsWithPendingAutomatic(ctx)
	if err != nil {
		return 0, fmt.Errorf("list tenants with pending attribution: %w", err)
	}
	total := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		names, err := j.Reevaluate(ctx, t)
		if err != nil {
			j.log.Warn("scope join re-evaluation failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
			continue
		}
		total += len(names)
	}
	return total, nil
}
