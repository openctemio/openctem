package asset

// Governance of edits that lower an asset's risk inputs
// (docs/architecture/asset-risk-governance.md). The decision lives in
// finding.AssetRiskGovernance; this file is the asset service's side: it asks
// before an edit that lowers exposure, criticality or the crown-jewel flag
// is applied, holds the lowered fields when the decision is "wait for
// approval", and applies them later through the same code path.

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RiskContext is who edits and what they said; the HTTP handlers set it so the
// edit is governed. A nil RiskContext (internal callers such as an approved
// request, a sensor or a scan) is not governed.
type RiskContext struct {
	// CanApprove: the caller holds findings:approve (they may decide alone
	// where the organization's level allows it).
	CanApprove bool
	// Reason is why the risk is lowered; required when the edit would drop an
	// open P0/P1 finding.
	Reason string
	Audit  auditapp.AuditContext
}

// RiskGovernInput is one edit that lowers risk inputs.
type RiskGovernInput struct {
	TenantID, AssetID shared.ID
	Before, After     assetdom.PriorityInputs
	Actor             shared.ID
	CanApprove        bool
	Reason            string
	Audit             auditapp.AuditContext
}

// RiskGovernOutcome is the decision: Held is set when the lowered fields wait
// for approval and must not be applied now.
type RiskGovernOutcome struct {
	Held *assetdom.RiskChangeRequest
}

// RiskGovernor decides edits that lower risk inputs.
type RiskGovernor interface {
	GovernRisk(ctx context.Context, in RiskGovernInput) (RiskGovernOutcome, error)
}

// SetRiskGovernor wires the decision of risk-lowering edits. Without it
// edits are not governed.
func (s *AssetService) SetRiskGovernor(g RiskGovernor) { s.riskGovernor = g }

// governLowering asks the governor about a proposed change of the asset's
// inputs; it answers the request that holds the lowered fields, or nil when
// the edit may apply.
func (s *AssetService) governLowering(ctx context.Context, a *assetdom.Asset, proposed assetdom.PriorityInputs, actorID string, rc *RiskContext) (*assetdom.RiskChangeRequest, error) {
	if rc == nil || s.riskGovernor == nil {
		return nil, nil //nolint:nilnil // not governed
	}
	before := assetdom.PriorityInputsOf(a)
	if len(assetdom.LoweredFields(before, proposed)) == 0 {
		return nil, nil //nolint:nilnil // raising risk is free
	}
	actor, _ := shared.IDFromString(actorID)
	out, err := s.riskGovernor.GovernRisk(ctx, RiskGovernInput{
		TenantID: a.TenantID(), AssetID: a.ID(), Before: before, After: proposed,
		Actor: actor, CanApprove: rc.CanApprove, Reason: rc.Reason, Audit: rc.Audit,
	})
	if err != nil {
		return nil, err
	}
	return out.Held, nil
}

// heldField reports whether the request holds the named field.
func heldField(req *assetdom.RiskChangeRequest, field string) bool {
	if req == nil {
		return false
	}
	for _, f := range req.Lowered {
		if f == field {
			return true
		}
	}
	return false
}

// ApplyLoweredRiskInputs applies the lowered fields of an approved request
// (finding.AssetRiskApplier) through the ordinary, ungoverned edit path: the
// values become the requester's locks, the asset is rescored and the change is
// on its timeline.
func (s *AssetService) ApplyLoweredRiskInputs(ctx context.Context, tenantID, assetID shared.ID, to assetdom.PriorityInputs, fields []string, actor shared.ID) error {
	in := UpdateAssetInput{ActorID: actor.String()}
	crown := false
	for _, f := range fields {
		switch f {
		case "exposure":
			v := string(to.Exposure)
			in.Exposure = &v
		case "criticality":
			v := string(to.Criticality)
			in.Criticality = &v
		case "crown_jewel":
			crown = true
		default:
			return fmt.Errorf("%w: unknown risk field %q", shared.ErrValidation, f)
		}
	}
	if in.Exposure != nil || in.Criticality != nil {
		if _, _, err := s.updateAsset(ctx, assetID.String(), tenantID.String(), in, nil); err != nil {
			return err
		}
	}
	if crown {
		a, err := s.repo.GetByID(ctx, tenantID, assetID)
		if err != nil {
			return err
		}
		score, notes := crownJewelImpact(a)
		if err := s.repo.SetCrownJewel(ctx, tenantID, assetID, to.CrownJewel, score, notes); err != nil {
			return err
		}
	}
	return nil
}

// crownJewelImpact is the business impact an asset already records, so
// unmarking it leaves the notes as they are.
func crownJewelImpact(a *assetdom.Asset) (float64, string) {
	var score float64
	switch v := a.Properties()[assetdom.PropKeyBusinessImpactScore].(type) {
	case float64:
		score = v
	case int:
		score = float64(v)
	}
	notes, _ := a.Properties()[assetdom.PropKeyBusinessImpactNotes].(string)
	return score, strings.TrimSpace(notes)
}

// UpdateAssetGoverned is UpdateAsset for a person's edit: when it lowers
// exposure or criticality and the organization's approval policy holds that,
// the lowered fields are not applied (the returned request waits for approval)
// and the rest of the edit is.
func (s *AssetService) UpdateAssetGoverned(ctx context.Context, assetID, tenantID string, input UpdateAssetInput, rc RiskContext) (*assetdom.Asset, *assetdom.RiskChangeRequest, error) {
	return s.updateAsset(ctx, assetID, tenantID, input, &rc)
}

// UpdateCrownJewelGoverned is UpdateCrownJewel for a person's edit: removing
// the flag from a crown jewel may wait for approval; the business impact is
// recorded either way.
func (s *AssetService) UpdateCrownJewelGoverned(ctx context.Context, tenantID, assetID string, isCrownJewel bool, impactScore float64, impactNotes, actorID string, rc RiskContext) (*assetdom.Asset, *assetdom.RiskChangeRequest, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, nil, shared.ErrNotFound
	}
	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, nil, err
	}
	proposed := assetdom.PriorityInputsOf(a)
	proposed.CrownJewel = isCrownJewel
	held, err := s.governLowering(ctx, a, proposed, actorID, &rc)
	if err != nil {
		return nil, nil, err
	}
	if heldField(held, "crown_jewel") {
		isCrownJewel = a.IsCrownJewel()
	}
	if err := s.repo.SetCrownJewel(ctx, parsedTenantID, parsedID, isCrownJewel, impactScore, impactNotes); err != nil {
		return nil, nil, err
	}
	out, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	return out, held, err
}

// LockAttributeGoverned is LockAttribute for a person's edit: locking
// exposure or criticality to a lower value may wait for approval (the view is
// then the current one and the request is returned).
func (s *AssetService) LockAttributeGoverned(ctx context.Context, tenantID, assetID, attribute, value, actorID string, rc RiskContext) (*AttributeSourcesView, *assetdom.RiskChangeRequest, error) {
	attr := assetdom.TrackedAttribute(attribute)
	if attr == assetdom.AttrExposure || attr == assetdom.AttrCriticality {
		v, err := assetdom.NormalizeAttributeValue(attr, value)
		if err != nil {
			return nil, nil, err
		}
		a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
		if err != nil {
			return nil, nil, err
		}
		proposed := assetdom.PriorityInputsOf(a)
		if attr == assetdom.AttrExposure {
			proposed.Exposure = assetdom.Exposure(v)
		} else {
			proposed.Criticality = assetdom.Criticality(v)
		}
		held, err := s.governLowering(ctx, a, proposed, actorID, &rc)
		if err != nil {
			return nil, nil, err
		}
		if held != nil {
			view, err := s.attributeView(ctx, tenantID, assetID, attr)
			return view, held, err
		}
	}
	view, err := s.LockAttribute(ctx, tenantID, assetID, attribute, value, actorID)
	return view, nil, err
}
