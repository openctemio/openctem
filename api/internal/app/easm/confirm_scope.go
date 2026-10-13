package easm

// A person's Confirm adds the asset's exact scope entry (research/117 F2,
// RFC-054 §14 R3). Saying "this is ours" on the attack surface used to
// record ownership only, so the person had to repeat the decision in a scope
// dialog before anything could be scanned. Now, while the organization's
// scan approval is Off or On and its setting confirm_adds_to_scope is on
// (the default), confirming a domain, subdomain or public address adds the
// exact entry for its name through the scope service: the same guardrails,
// deny list, signer ledger, step-up and one notice to the administrators per
// batch as any bulk add. Strict keeps the old behavior (ownership only), and
// so does a caller without the scope write permission.
//
// Never added: an entry wider than the name (no wildcard, no range), an
// entry for a name an active entry already covers, an entry for a private
// or internal name (scan zones gate those), and an entry for a service,
// certificate or web endpoint (they follow their host).

import (
	"context"
	"errors"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ConfirmScopeTargets adds scope entries and reports the scan approval mode
// in force (*scope.Service).
type ConfirmScopeTargets interface {
	CreateTargets(ctx context.Context, in scope.BulkTargetsInput) ([]scope.BulkTargetOutcome, error)
	ApprovalPolicy(ctx context.Context, tenantID string) (scangov.Mode, string)
}

// ConfirmScopeSettings reads the organization's scope settings
// (*tenant.TenantService).
type ConfirmScopeSettings interface {
	GetScopeSettings(ctx context.Context, tenantID string) (*tenant.ScopeSettings, error)
}

// ScopeActor is the person deciding: who they are, whether they may approve
// scope entries, and whether they may write scope at all.
type ScopeActor struct {
	scope.Actor
	CanWriteScope bool
}

// Why no entry was added for a whole decision.
const (
	ConfirmSkippedDisabled     = "disabled"          // the organization turned the setting off
	ConfirmSkippedStrict       = "strict"            // scan approval is Strict
	ConfirmSkippedNoPermission = "needs_scope_write" // the caller may not write scope
)

// What happened to one confirmed asset's entry.
const (
	EntryAdded   = "added"   // a new entry (active, or pending its approval)
	EntryExists  = "exists"  // the organization already has this exact entry
	EntryCovered = "covered" // an active entry already covers the name
	EntryRefused = "refused" // the scope service refused it (code says why)
)

// ConfirmedEntry is the scope entry of one confirmed asset.
type ConfirmedEntry struct {
	AssetID    string `json:"asset_id"`
	Name       string `json:"name"`
	TargetType string `json:"target_type,omitempty"`
	Pattern    string `json:"pattern,omitempty"`
	// TargetID: the entry added (undo deletes it) or the one that already
	// exists or covers the name.
	TargetID string `json:"target_id,omitempty"`
	// Status of an added entry: active, or pending its approvals.
	Status  string `json:"status,omitempty"`
	Outcome string `json:"outcome"`
	// Code: why the scope service refused it (DENY_LIST, PUBLIC_SUFFIX, ...).
	Code string `json:"code,omitempty"`
}

// ConfirmScopeResult is what a confirmation did to scope.
type ConfirmScopeResult struct {
	// Skipped says why no entry was considered at all (empty: considered).
	Skipped string           `json:"skipped,omitempty"`
	Entries []ConfirmedEntry `json:"entries"`
}

// ConfirmScope adds the exact entries of confirmed assets.
type ConfirmScope struct {
	targets  ConfirmScopeTargets
	settings ConfirmScopeSettings
	assets   ActiveGateAssets
	coverage ReviewCoverage
}

// NewConfirmScope creates it. Every dependency is required; a nil one makes
// Add add nothing (ownership only, as before).
func NewConfirmScope(targets ConfirmScopeTargets, settings ConfirmScopeSettings, assets ActiveGateAssets, coverage ReviewCoverage) *ConfirmScope {
	return &ConfirmScope{targets: targets, settings: settings, assets: assets, coverage: coverage}
}

func (c *ConfirmScope) ready() bool {
	return c != nil && c.targets != nil && c.settings != nil && c.assets != nil && c.coverage != nil
}

// skipped answers why nothing is added for this organization and caller
// ("" when entries are added). An unreadable setting adds nothing: a
// confirmation never gains authority it cannot show it was given.
func (c *ConfirmScope) skipped(ctx context.Context, tenantID shared.ID, actor ScopeActor) string {
	if !c.ready() {
		return ConfirmSkippedDisabled
	}
	if mode, _ := c.targets.ApprovalPolicy(ctx, tenantID.String()); mode.Normalized() == scangov.ModeStrict {
		return ConfirmSkippedStrict
	}
	st, err := c.settings.GetScopeSettings(ctx, tenantID.String())
	if err != nil || st == nil || st.ConfirmAddsToScopeDisabled {
		return ConfirmSkippedDisabled
	}
	if !actor.CanWriteScope || actor.UserID == "" {
		return ConfirmSkippedNoPermission
	}
	return ""
}

// exactEntry is the entry type and pattern of an asset's own name, or
// ok=false when the asset gets no entry of its own.
func exactEntry(a *asset.Asset) (scopedom.TargetType, string, bool) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.Name()), "."))
	if name == "" || !scopedom.NeedsAuthority(name) {
		return "", "", false
	}
	switch asset.CanonicalPair(a.Type(), a.SubType()).Type {
	case asset.AssetTypeDomain, asset.AssetTypeSubdomain:
		if strings.HasPrefix(name, "*.") {
			return "", "", false // never wider than the name
		}
		return scopedom.TargetTypeDomain, name, true
	case asset.AssetTypeIPAddress:
		return scopedom.TargetTypeIPAddress, name, true
	}
	return "", "", false
}

// Add adds the exact entries of the given assets, which the caller already
// narrowed to the tenant and its data scope. A request-level error (step-up
// missing, the scope service unavailable) is returned before anything is
// written, so the caller saves no decision either.
func (c *ConfirmScope) Add(ctx context.Context, tenantID shared.ID, assetIDs []string, actor ScopeActor, reason string) (*ConfirmScopeResult, error) {
	out := &ConfirmScopeResult{Entries: []ConfirmedEntry{}}
	if why := c.skipped(ctx, tenantID, actor); why != "" {
		out.Skipped = why
		return out, nil
	}
	ids := make([]shared.ID, 0, len(assetIDs))
	for _, raw := range assetIDs {
		if id, err := shared.IDFromString(raw); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	found, err := c.assets.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	type planned struct {
		entry ConfirmedEntry
		typ   scopedom.TargetType
	}
	plan := make([]planned, 0, len(ids))
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		a := found[id.String()]
		if a == nil {
			continue
		}
		typ, pattern, ok := exactEntry(a)
		if !ok {
			continue
		}
		plan = append(plan, planned{entry: ConfirmedEntry{AssetID: id.String(), Name: a.Name(), TargetType: string(typ), Pattern: pattern}, typ: typ})
		names = append(names, pattern)
	}
	if len(plan) == 0 {
		return out, nil
	}
	cover, err := c.coverage.CoverOf(ctx, tenantID, names)
	if err != nil {
		return nil, err
	}
	items := make([]scope.BulkTargetItem, 0, len(plan))
	pending := make([]int, 0, len(plan)) // plan index of each item
	seen := map[string]int{}
	for i := range plan {
		p := &plan[i]
		if via, ok := cover[p.entry.Pattern]; ok {
			p.entry.Outcome, p.entry.TargetID = EntryCovered, via.ID
			continue
		}
		if _, dup := seen[p.entry.Pattern]; dup {
			continue
		}
		seen[p.entry.Pattern] = i
		items = append(items, scope.BulkTargetItem{TargetType: string(p.typ), Pattern: p.entry.Pattern})
		pending = append(pending, i)
	}
	if len(items) > 0 {
		outcomes, err := c.targets.CreateTargets(ctx, scope.BulkTargetsInput{
			TenantID: tenantID.String(), Items: items, Reason: reason, CreatedBy: actor.UserID,
			Actor: actor.Actor, Origin: scopedom.OriginConfirmed,
		})
		if err != nil {
			return nil, err
		}
		for k, o := range outcomes {
			if k >= len(pending) {
				break
			}
			e := &plan[pending[k]].entry
			var dup *scopedom.DuplicateError
			var de *shared.DomainError
			switch {
			case o.Err == nil && o.Target != nil:
				e.Outcome, e.TargetID, e.Status = EntryAdded, o.Target.ID().String(), string(o.Target.Status())
			case errors.As(o.Err, &dup):
				e.Outcome = EntryExists
				if !dup.Existing.ID.IsZero() {
					e.TargetID = dup.Existing.ID.String()
				}
			case errors.As(o.Err, &de):
				e.Outcome, e.Code = EntryRefused, de.Code
			default:
				e.Outcome = EntryRefused
			}
		}
	}
	// Two assets with the same name share the first one's outcome.
	for i := range plan {
		if plan[i].entry.Outcome == "" {
			if j, ok := seen[plan[i].entry.Pattern]; ok && j != i {
				first := plan[j].entry
				plan[i].entry.Outcome, plan[i].entry.TargetID, plan[i].entry.Status, plan[i].entry.Code =
					first.Outcome, first.TargetID, first.Status, first.Code
			}
		}
		out.Entries = append(out.Entries, plan[i].entry)
	}
	return out, nil
}
