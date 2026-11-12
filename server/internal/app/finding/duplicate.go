package finding

// "Mark duplicate of" (RFC-043 §9): a user folds one finding into another.
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// duplicateMarker is implemented by the postgres finding repository.
type duplicateMarker interface {
	MarkDuplicateOf(ctx context.Context, tenantID, duplicateID, canonicalID shared.ID, actorID string) error
}

// MarkDuplicateInput marks FindingID a duplicate of DuplicateOfID.
type MarkDuplicateInput struct {
	TenantID      string
	FindingID     string
	DuplicateOfID string
	// ActorID is the authenticated user.
	ActorID string
	Audit   audit.AuditContext
}

// MarkDuplicateOf folds a finding into the one it duplicates: both must be in
// the caller's tenant and data scope, on the same asset, and neither already
// a duplicate. The canonical finding inherits the stronger state and every
// reference (comments, retests, evidence, activities, tickets, keys); the
// duplicate stays as a tombstone. Returns the canonical finding.
func (s *VulnerabilityService) MarkDuplicateOf(ctx context.Context, in MarkDuplicateInput) (*vulnerability.Finding, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	dupID, err := shared.IDFromString(in.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	canonID, err := shared.IDFromString(in.DuplicateOfID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid duplicate_of_id format", shared.ErrValidation)
	}
	marker, ok := s.findingRepo.(duplicateMarker)
	if !ok {
		return nil, fmt.Errorf("%w: marking duplicates is not available", shared.ErrValidation)
	}

	// Both findings: tenant-scoped reads, then the caller's data scope. Either
	// one outside it is "not found", never "forbidden", so the response does
	// not confirm that it exists.
	dup, err := s.findingRepo.GetByID(ctx, tenantID, dupID)
	if err != nil {
		return nil, err
	}
	if err := s.assertFindingScope(ctx, dup); err != nil {
		return nil, err
	}
	canon, err := s.findingRepo.GetByID(ctx, tenantID, canonID)
	if err != nil {
		return nil, err
	}
	if err := s.assertFindingScope(ctx, canon); err != nil {
		return nil, err
	}
	if err := vulnerability.CheckMarkDuplicate(duplicateCandidate(dup), duplicateCandidate(canon)); err != nil {
		return nil, err
	}

	// The repository locks both rows and checks the rules again before it
	// merges, so a concurrent change cannot slip between.
	if err := marker.MarkDuplicateOf(ctx, tenantID, dupID, canonID, in.ActorID); err != nil {
		return nil, err
	}
	s.auditDuplicateMarked(ctx, in, dup, canon)

	return s.findingRepo.GetByID(ctx, tenantID, canonID)
}

func duplicateCandidate(f *vulnerability.Finding) vulnerability.DuplicateCandidate {
	return vulnerability.DuplicateCandidate{ID: f.ID(), AssetID: f.AssetID(), Status: f.Status(), Source: f.Source()}
}

func (s *VulnerabilityService) auditDuplicateMarked(ctx context.Context, in MarkDuplicateInput, dup, canon *vulnerability.Finding) {
	if s.auditService == nil {
		return
	}
	actx := in.Audit
	if actx.TenantID == "" {
		actx.TenantID = in.TenantID
	}
	if actx.ActorID == "" {
		actx.ActorID = in.ActorID
	}
	event := audit.NewSuccessEvent(auditdom.ActionFindingDuplicateMarked, auditdom.ResourceTypeFinding, dup.ID().String()).
		WithMessage("Marked a finding as a duplicate of another").
		WithMetadata("duplicate_of", canon.ID().String()).
		WithMetadata("asset_id", dup.AssetID().String()).
		WithMetadata("duplicate_status", dup.Status().String()).
		WithMetadata("canonical_status", canon.Status().String()).
		WithSeverity(auditdom.SeverityMedium)
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit duplicate marking", "error", err)
	}
}

// auditFindingDeleted records the deletion of a finding before it happens.
// It returns the write error so the caller can refuse the delete.
func (s *VulnerabilityService) auditFindingDeleted(ctx context.Context, actx audit.AuditContext, f *vulnerability.Finding) error {
	if s.auditService == nil {
		return nil
	}
	if actx.TenantID == "" {
		actx.TenantID = f.TenantID().String()
	}
	event := audit.NewSuccessEvent(auditdom.ActionFindingDeleted, auditdom.ResourceTypeFinding, f.ID().String()).
		WithResourceName(f.Title()).
		WithMessage("Deleted a finding and its activity timeline").
		WithSeverity(auditdom.SeverityHigh).
		WithMetadata("severity", f.Severity().String()).
		WithMetadata("status", f.Status().String()).
		WithMetadata("source", string(f.Source())).
		WithMetadata("cve_id", f.CVEID()).
		WithMetadata("asset_id", f.AssetID().String()).
		WithMetadata("fingerprint", f.Fingerprint()).
		WithMetadata("tool_name", f.ToolName())
	if s.activityService != nil {
		// The timeline is removed with the row; the count says how much
		// history went with it. A count failure does not block the audit.
		if n, err := s.activityService.CountActivities(ctx, f.TenantID().String(), f.ID().String(), vulnerability.FindingActivityFilter{}); err == nil {
			event = event.WithMetadata("activities_removed", n)
		}
	}
	return s.auditService.LogEvent(ctx, actx, event)
}
