package asset

// Attribute reconciliation (RFC-069,
// docs/architecture/asset-attribute-reconciliation.md): every source's value
// of a tracked attribute is recorded, and the asset shows the value of the
// most trusted, most recent one. A person's change is a lock.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ReconciliationSettingsReader reads a tenant's settings for its
// reconciliation policy.
type ReconciliationSettingsReader interface {
	GetByID(ctx context.Context, id shared.ID) (*tenantdom.Tenant, error)
}

// SetAttributeSources wires attribute reconciliation. Unwired, edits and
// ingest behave as before and no source is recorded.
func (s *AssetService) SetAttributeSources(repo assetdom.AttributeSourceRepository, tenants ReconciliationSettingsReader) {
	s.attrSources = repo
	s.attrTenants = tenants
}

// ReconciliationPolicy returns the tenant's policy; the defaults when it set
// none or its settings cannot be read.
func (s *AssetService) ReconciliationPolicy(ctx context.Context, tenantID shared.ID) assetdom.ReconciliationPolicy {
	if s.attrTenants == nil {
		return assetdom.DefaultReconciliationPolicy()
	}
	t, err := s.attrTenants.GetByID(ctx, tenantID)
	if err != nil || t == nil {
		s.logger.Warn("reconciliation policy: tenant settings unreadable, using the defaults", "tenant_id", tenantID.String())
		return assetdom.DefaultReconciliationPolicy()
	}
	p, err := t.TypedSettings().AssetReconciliation.Policy()
	if err != nil {
		s.logger.Warn("reconciliation policy: invalid settings, using the defaults", "tenant_id", tenantID.String(), "error", err)
		return assetdom.DefaultReconciliationPolicy()
	}
	return p
}

// ReconcileAttributes records observations of the tenant's assets (from
// ingest) and applies the values they decide. The caller decided each
// observation's kind from how the data arrived.
func (s *AssetService) ReconcileAttributes(ctx context.Context, tenantID shared.ID, obs []assetdom.AttributeObservation) error {
	if s.attrSources == nil || len(obs) == 0 {
		return nil
	}
	_, err := s.applyAttributes(ctx, tenantID, assetdom.AttributeApply{Observations: obs}, nil)
	return err
}

func (s *AssetService) applyAttributes(ctx context.Context, tenantID shared.ID, in assetdom.AttributeApply, actor *shared.ID) ([]assetdom.AttributeChange, error) {
	in.Policy = s.ReconciliationPolicy(ctx, tenantID)
	in.Now = time.Now()
	in.Actor = actor
	res, err := s.attrSources.Apply(ctx, tenantID, in)
	if err != nil {
		return nil, fmt.Errorf("reconcile attributes: %w", err)
	}
	for v, n := range res.Verdicts {
		metrics.AssetAttributeObservationsTotal.WithLabelValues(string(v)).Add(float64(n))
	}
	metrics.AssetChangeEventsTotal.Add(float64(res.Events))
	s.afterAttributeChanges(ctx, tenantID, res.Changes, actor)
	return res.Changes, nil
}

// ResolveAttributes re-resolves the tracked attributes of the tenant's
// assets without new observations (a policy change, a source past its TTL)
// and applies what changed; reason is the timeline reason of each change.
func (s *AssetService) ResolveAttributes(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, reason assetdom.ChangeReason) (int, error) {
	if s.attrSources == nil || len(assetIDs) == 0 {
		return 0, nil
	}
	refs := make([]assetdom.AttributeRef, 0, len(assetIDs)*len(assetdom.AllTrackedAttributes()))
	for _, id := range assetIDs {
		for _, attr := range assetdom.AllTrackedAttributes() {
			refs = append(refs, assetdom.AttributeRef{AssetID: id, Attribute: attr})
		}
	}
	changes, err := s.applyAttributes(ctx, tenantID, assetdom.AttributeApply{Resolve: refs, Reason: reason}, nil)
	return len(changes), err
}

// afterAttributeChanges records each change in the asset history, re-scores
// assets whose criticality or exposure changed and keeps the owner derived
// from owner_ref in step. Best-effort.
func (s *AssetService) afterAttributeChanges(ctx context.Context, tenantID shared.ID, changes []assetdom.AttributeChange, actor *shared.ID) {
	rescore := map[shared.ID]bool{}
	for _, c := range changes {
		ch := assetdom.RecordFieldChange(tenantID, c.AssetID, assetdom.StateChangeFor(c.Attribute),
			string(c.Attribute), c.Old, c.New, assetdom.ChangeSourceFor(c.Source.Kind), nil)
		if c.Source.Kind == assetdom.SourceKindManual {
			ch.SetChangedBy(actor)
		}
		ch.SetReason(fmt.Sprintf("%s: decided by %s source %s, observed %s", c.Reason,
			c.Source.Kind, sourceLabel(c.Source.Name), c.Source.ObservedAt.UTC().Format(time.RFC3339)))
		s.recordStateChange(ctx, ch)
		switch c.Attribute {
		case assetdom.AttrCriticality, assetdom.AttrExposure:
			rescore[c.AssetID] = true
		case assetdom.AttrOwnerRef:
			s.syncOwnerRefOwner(ctx, tenantID, c.AssetID, c.New)
		}
	}
	if len(rescore) == 0 {
		return
	}
	assets := make([]*assetdom.Asset, 0, len(rescore))
	for id := range rescore {
		a, err := s.repo.GetByID(ctx, tenantID, id)
		if err != nil {
			continue
		}
		s.scoreAsset(ctx, tenantID, a)
		assets = append(assets, a)
	}
	if err := s.repo.BatchUpdateRiskScores(ctx, tenantID, assets); err != nil {
		s.logger.Warn("risk score update after reconciliation failed", "tenant_id", tenantID.String(), "error", err)
	}
}

func sourceLabel(name string) string {
	if strings.TrimSpace(name) == "" {
		return "-"
	}
	return name
}

// recordManualAttributes records a person's values as locks. With before,
// a value equal to the asset's value before the edit is not locked: a form
// that echoes every field locks only what the person changed.
func (s *AssetService) recordManualAttributes(ctx context.Context, tenantID, assetID shared.ID, actorID string,
	values map[assetdom.TrackedAttribute]string, before map[assetdom.TrackedAttribute]string,
) {
	if s.attrSources == nil || len(values) == 0 {
		return
	}
	now := time.Now()
	name := actorID
	if name == "" {
		name = "api"
	}
	obs := make([]assetdom.AttributeObservation, 0, len(values))
	for attr, v := range values {
		if before != nil && before[attr] == v {
			continue
		}
		obs = append(obs, assetdom.AttributeObservation{
			AssetID: assetID, Attribute: attr, Kind: assetdom.SourceKindManual, Name: name,
			Value: v, ObservedAt: now, Confidence: 100,
		})
	}
	if len(obs) == 0 {
		return
	}
	var actor *shared.ID
	if id, err := shared.IDFromString(actorID); err == nil {
		actor = &id
	}
	if _, err := s.applyAttributes(ctx, tenantID, assetdom.AttributeApply{Observations: obs}, actor); err != nil {
		s.logger.Warn("manual attribute lock not recorded", "asset_id", assetID.String(), "error", err)
	}
}

// AttributeSourcesView is, per tracked attribute, the asset's value and why.
type AttributeSourcesView struct {
	Attribute assetdom.TrackedAttribute
	Value     string
	Locked    bool
	Conflict  bool
	// Winner is the deciding source; nil when none may decide (the value
	// predates source tracking or every source is stale or untrusted).
	Winner     *assetdom.AttributeObservation
	Candidates []assetdom.Candidate
}

// GetAttributeSources returns every tracked attribute of an asset the caller
// may see, with the source that decides it and every other source's value.
func (s *AssetService) GetAttributeSources(ctx context.Context, tenantID, assetID string) ([]AttributeSourcesView, error) {
	a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	var obs []assetdom.AttributeObservation
	if s.attrSources != nil {
		if obs, err = s.attrSources.ListForAsset(ctx, a.TenantID(), a.ID()); err != nil {
			return nil, fmt.Errorf("list attribute sources: %w", err)
		}
	}
	p := s.ReconciliationPolicy(ctx, a.TenantID())
	now := time.Now()
	out := make([]AttributeSourcesView, 0, len(assetdom.AllTrackedAttributes()))
	for _, attr := range assetdom.AllTrackedAttributes() {
		r := assetdom.ResolveFrom(attr, obs, p, now, a.AttributeValue(attr))
		out = append(out, AttributeSourcesView{
			Attribute: attr, Value: a.AttributeValue(attr), Locked: r.Locked, Conflict: r.Conflict,
			Winner: r.Winner, Candidates: r.Candidates,
		})
	}
	return out, nil
}

// LockAttribute sets an attribute of an asset the caller may see to value
// and locks it: no source changes it until the lock is released.
func (s *AssetService) LockAttribute(ctx context.Context, tenantID, assetID, attribute, value, actorID string) (*AttributeSourcesView, error) {
	attr := assetdom.TrackedAttribute(attribute)
	if !attr.IsValid() {
		return nil, fmt.Errorf("%w: unknown attribute %q", shared.ErrValidation, attribute)
	}
	v, err := assetdom.NormalizeAttributeValue(attr, value)
	if err != nil {
		return nil, err
	}
	if s.attrSources == nil {
		return nil, fmt.Errorf("%w: attribute sources are not configured", shared.ErrValidation)
	}
	a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	var actor *shared.ID
	if id, perr := shared.IDFromString(actorID); perr == nil {
		actor = &id
	}
	obs := assetdom.AttributeObservation{
		AssetID: a.ID(), Attribute: attr, Kind: assetdom.SourceKindManual, Name: actorID,
		Value: v, ObservedAt: time.Now(), Confidence: 100,
	}
	if _, err := s.applyAttributes(ctx, a.TenantID(), assetdom.AttributeApply{Observations: []assetdom.AttributeObservation{obs}}, actor); err != nil {
		return nil, err
	}
	return s.attributeView(ctx, tenantID, assetID, attr)
}

// ReleaseAttributeLock removes the lock of an attribute of an asset the
// caller may see; the attribute is decided by its sources again.
func (s *AssetService) ReleaseAttributeLock(ctx context.Context, tenantID, assetID, attribute, actorID string) (*AttributeSourcesView, error) {
	attr := assetdom.TrackedAttribute(attribute)
	if !attr.IsValid() {
		return nil, fmt.Errorf("%w: unknown attribute %q", shared.ErrValidation, attribute)
	}
	if s.attrSources == nil {
		return nil, fmt.Errorf("%w: attribute sources are not configured", shared.ErrValidation)
	}
	a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	var actor *shared.ID
	if id, perr := shared.IDFromString(actorID); perr == nil {
		actor = &id
	}
	in := assetdom.AttributeApply{Release: []assetdom.AttributeRef{{AssetID: a.ID(), Attribute: attr}}}
	if _, err := s.applyAttributes(ctx, a.TenantID(), in, actor); err != nil {
		return nil, err
	}
	return s.attributeView(ctx, tenantID, assetID, attr)
}

func (s *AssetService) attributeView(ctx context.Context, tenantID, assetID string, attr assetdom.TrackedAttribute) (*AttributeSourcesView, error) {
	views, err := s.GetAttributeSources(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	for i := range views {
		if views[i].Attribute == attr {
			return &views[i], nil
		}
	}
	return nil, shared.ErrNotFound
}

// attributeSnapshot returns the asset's tracked values.
func attributeSnapshot(a *assetdom.Asset) map[assetdom.TrackedAttribute]string {
	out := make(map[assetdom.TrackedAttribute]string, 4)
	for _, attr := range assetdom.AllTrackedAttributes() {
		out[attr] = a.AttributeValue(attr)
	}
	return out
}

// editedAttributes returns the asset's values of the attributes an edit set.
func editedAttributes(a *assetdom.Asset, criticality, exposure, ownerRef bool) map[assetdom.TrackedAttribute]string {
	out := map[assetdom.TrackedAttribute]string{}
	if criticality {
		out[assetdom.AttrCriticality] = a.AttributeValue(assetdom.AttrCriticality)
	}
	if exposure {
		out[assetdom.AttrExposure] = a.AttributeValue(assetdom.AttrExposure)
	}
	if ownerRef {
		out[assetdom.AttrOwnerRef] = a.AttributeValue(assetdom.AttrOwnerRef)
	}
	return out
}

// AttributeSourceSummaries lists the sources that reported the tenant's
// assets (for the precedence settings).
func (s *AssetService) AttributeSourceSummaries(ctx context.Context, tenantID shared.ID) ([]assetdom.SourceSummary, error) {
	if s.attrSources == nil {
		return nil, nil
	}
	return s.attrSources.SourceSummaries(ctx, tenantID)
}

// maxPreviewAssets bounds how many assets a precedence preview resolves.
const maxPreviewAssets = 5000

// PreviewReconciliationPolicy reports what p would change on the tenant's
// assets with a recorded source (at most maxPreviewAssets), or on the one
// asset assetID when given. It writes nothing.
func (s *AssetService) PreviewReconciliationPolicy(ctx context.Context, tenantID shared.ID, p assetdom.ReconciliationPolicy, assetID *shared.ID) (*assetdom.PolicyPreview, error) {
	pv := &assetdom.PolicyPreview{}
	if s.attrSources == nil {
		return pv, nil
	}
	now := time.Now()
	if assetID != nil {
		snaps, err := s.attrSources.Snapshot(ctx, tenantID, []shared.ID{*assetID})
		if err != nil {
			return nil, err
		}
		if len(snaps) == 0 {
			return nil, shared.ErrNotFound
		}
		assetdom.PreviewSnapshots(pv, snaps, p, now)
		return pv, nil
	}
	if s.attrLister == nil {
		return pv, nil
	}
	var after *shared.ID
	for pv.ScannedAssets < maxPreviewAssets {
		ids, err := s.attrLister.AssetsWithAttributeSources(ctx, tenantID, after, reResolveBatch)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return pv, nil
		}
		snaps, err := s.attrSources.Snapshot(ctx, tenantID, ids)
		if err != nil {
			return nil, err
		}
		assetdom.PreviewSnapshots(pv, snaps, p, now)
		if len(ids) < reResolveBatch {
			return pv, nil
		}
		last := ids[len(ids)-1]
		after = &last
	}
	if more, err := s.attrLister.AssetsWithAttributeSources(ctx, tenantID, after, 1); err == nil && len(more) > 0 {
		pv.Truncated = true
	}
	return pv, nil
}
