package scope

// A person confirming an asset as the organization's also puts it in scope
// (RFC-054 §14, R3): the exact entry for its name or address is added
// through CreateTargets, so the guardrails, the signer ledger, audit and the
// batch notice apply as for any entry, and step-up is asked for once. Only
// in the Off and On scan approval modes (Strict keeps scope changes behind
// approvals) and while the organization's confirm_adds_to_scope setting is
// on. Exclusions and tombstones still win at dispatch.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// assetsByID loads the tenant's assets by id (*postgres.AssetRepository).
type assetsByID interface {
	GetByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]*asset.Asset, error)
}

// scopeEntryAssetTypes are the stored asset types whose name a scope entry
// covers: names, addresses, networks and the services and applications on
// them. Hosts, repositories, cloud resources and identities are not judged
// by scope entries.
var scopeEntryAssetTypes = map[asset.AssetType]bool{
	asset.AssetTypeDomain:      true,
	asset.AssetTypeSubdomain:   true,
	asset.AssetTypeIPAddress:   true,
	asset.AssetTypeNetwork:     true,
	asset.AssetTypeService:     true,
	asset.AssetTypeApplication: true,
}

// ConfirmCoverage is what confirming assets did to scope.
type ConfirmCoverage struct {
	// Added entries now in effect, and assets an entry already covered.
	Added   int `json:"added"`
	Covered int `json:"covered"`
	// Refused items (guardrails, the signer), with the first reason.
	Refused       int    `json:"refused"`
	RefusedReason string `json:"refused_reason,omitempty"`
	// StepUpRequired: nothing was added because the caller has not
	// re-authenticated recently; Pending are the entries to add with
	// POST /scope/targets/bulk once they have.
	StepUpRequired bool             `json:"step_up_required,omitempty"`
	Pending        []BulkTargetItem `json:"pending,omitempty"`
}

// CoverConfirmedAssets adds the exact scope entry of each confirmed asset
// nothing covers yet. It answers nil when the rule does not apply (Strict,
// the setting off, a system actor, nothing to add). assetIDs are assets the
// caller just confirmed (already limited to the caller's data scope); ids of
// another tenant are not found by the tenant-scoped read.
func (s *Service) CoverConfirmedAssets(ctx context.Context, tenantID string, actor Actor, assetIDs []string) (*ConfirmCoverage, error) {
	if actor.system() || len(assetIDs) == 0 {
		return nil, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	p, err := s.loadPolicy(ctx, tid)
	if err != nil {
		return nil, err
	}
	if p.twoPerson() || !p.settings.ConfirmAddsToScope() {
		return nil, nil
	}
	reader, ok := s.assetRepo.(assetsByID)
	if !ok {
		return nil, errors.New("scope: asset lookup by id is not wired")
	}
	ids := make([]shared.ID, 0, len(assetIDs))
	for _, raw := range assetIDs {
		if id, err := shared.IDFromString(raw); err == nil {
			ids = append(ids, id)
		}
	}
	assets, err := reader.GetByIDs(ctx, tid, ids)
	if err != nil {
		return nil, fmt.Errorf("load confirmed assets: %w", err)
	}
	active, err := s.targetRepo.ListActive(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("list scope entries: %w", err)
	}
	out := &ConfirmCoverage{}
	items := make([]BulkTargetItem, 0, len(assets))
	seen := map[string]bool{}
	now := time.Now()
	for _, a := range assets {
		if a == nil || !scopeEntryAssetTypes[asset.CanonicalPair(a.Type(), a.SubType()).Type] {
			continue
		}
		typ, pattern, ok := scopedom.ExactEntryFor(a.Name())
		if !ok {
			continue
		}
		if coveredByAny(active, pattern, now) {
			out.Covered++
			continue
		}
		key := string(typ) + ":" + pattern
		if seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, BulkTargetItem{TargetType: string(typ), Pattern: pattern})
	}
	if len(items) == 0 {
		if out.Covered == 0 {
			return nil, nil
		}
		return out, nil
	}
	if len(items) > MaxBulkTargets {
		items = items[:MaxBulkTargets]
	}
	// Confirming needs no step-up; widening scope does. Without a recent
	// re-authentication nothing is added and the caller is told what to add.
	if err := s.requireStepUp(ctx, actor); err != nil {
		out.StepUpRequired, out.Pending = true, items
		return out, nil //nolint:nilerr // a missing step-up is an answer, not a failure
	}
	outcomes, err := s.CreateTargets(ctx, BulkTargetsInput{
		TenantID: tenantID, Items: items, CreatedBy: actor.UserID, Actor: actor,
		Origin: scopedom.OriginManual, Reason: "Confirmed as the organization's asset",
	})
	if err != nil {
		return nil, err
	}
	for _, o := range outcomes {
		var dup *scopedom.DuplicateError
		switch {
		case o.Err == nil:
			out.Added++
		case errors.As(o.Err, &dup):
			out.Covered++
		default:
			out.Refused++
			if out.RefusedReason == "" {
				out.RefusedReason = refusalText(o.Err)
			}
		}
	}
	return out, nil
}

// coveredByAny reports whether an entry in effect covers the pattern.
func coveredByAny(ts []*scopedom.Target, pattern string, now time.Time) bool {
	for _, t := range ts {
		if t.InEffect(now) && t.Matches(pattern) {
			return true
		}
	}
	return false
}

func refusalText(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) && de.Message != "" {
		return de.Message
	}
	return "not added"
}
