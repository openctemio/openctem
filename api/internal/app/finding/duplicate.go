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
	MarkDuplicateOf(ctx context.Context, tenantID, duplicateID, canonicalID shared.ID, actorID string, canApprove bool) error
}

// MarkDuplicateInput marks FindingID a duplicate of DuplicateOfID.
type MarkDuplicateInput struct {
	TenantID      string
	FindingID     string
	DuplicateOfID string
	// ActorID is the authenticated user.
	ActorID string
	// CanApprove is whether the actor holds findings:approve, needed when
	// either finding is a false positive or a risk acceptance.
	CanApprove bool
	Audit      audit.AuditContext
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
	if err := vulnerability.CheckMarkDuplicate(duplicateCandidate(dup), duplicateCandidate(canon), in.CanApprove); err != nil {
		return nil, err
	}

	// The repository locks both rows and checks the rules again before it
	// merges, so a concurrent change cannot slip between.
	if err := marker.MarkDuplicateOf(ctx, tenantID, dupID, canonID, in.ActorID, in.CanApprove); err != nil {
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
