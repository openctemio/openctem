package cirun

// The gate baseline of a repository
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md, "Gate baseline"):
// recorded and removed by a person with the policy permission, never by a
// run or by the repository's own file.

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GetGateBaseline returns a repository's gate baseline
// (cirun.ErrBaselineNotFound when it has none).
func (s *Service) GetGateBaseline(ctx context.Context, tenantID, assetID shared.ID) (*cirun.GateBaseline, error) {
	b, err := s.repo.GateBaseline(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, cirun.ErrBaselineNotFound
	}
	return b, nil
}

// SetGateBaseline records the findings open now on the repository's default
// branch as its gate baseline. It lets those findings pass default-branch
// runs, so it needs a recent sign-in, is audited at high severity and is
// announced to every administrator. The caller has checked the repository
// is in their data scope.
func (s *Service) SetGateBaseline(ctx context.Context, tenantID, assetID shared.ID, a Actor) (*cirun.GateBaseline, error) {
	repo, err := s.assets.GetByID(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	if repo.Type() != asset.AssetTypeRepository {
		return nil, fmt.Errorf("%w: a gate baseline belongs to a repository", shared.ErrValidation)
	}
	if err := s.requireStepUpToLoosen(ctx, a, []string{"baseline"}); err != nil {
		return nil, err
	}
	b := &cirun.GateBaseline{TenantID: tenantID, RepositoryAssetID: assetID, Source: cirun.BaselineSourceManual,
		SetAt: s.now().UTC()}
	if uid, err := shared.IDFromString(a.UserID); err == nil {
		b.SetBy = &uid
	}
	if err := s.repo.SetGateBaseline(ctx, b); err != nil {
		return nil, err
	}
	name := repo.Name()
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGateBaselineSet, auditdom.ResourceTypeCIGateBaseline, assetID.String()).
		WithResourceName(name).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage(fmt.Sprintf("CI gate baseline recorded for %s: %d open findings on %s stop blocking default-branch runs",
			name, b.FindingsCount, nonEmpty(b.Branch, "the default branch"))).
		WithMetadata("findings", b.FindingsCount).
		WithMetadata("branch", b.Branch))
	aid := assetID
	s.alertAdmins(ctx, tenantID, breakGlassAlert(AdminAlert{
		Title: "CI gate baseline recorded: " + name,
		Body: fmt.Sprintf("%s recorded the CI gate baseline of %s: its %d open findings no longer fail default-branch runs.",
			nonEmpty(a.Email, "an administrator"), name, b.FindingsCount),
		URL: "/ci-cd", Aggregate: "ci_gate_baseline", AggregateID: &aid,
		Metadata: map[string]any{"action": "baseline_set", "repository": name, "findings": b.FindingsCount},
	}))
	return b, nil
}

// DeleteGateBaseline removes a repository's gate baseline: every finding on
// its default branch counts as new again (stricter; audited).
func (s *Service) DeleteGateBaseline(ctx context.Context, tenantID, assetID shared.ID, a Actor) error {
	if err := s.repo.DeleteGateBaseline(ctx, tenantID, assetID); err != nil {
		return err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIGateBaselineDeleted, auditdom.ResourceTypeCIGateBaseline, assetID.String()).
		WithMessage("CI gate baseline removed for repository "+assetID.String()))
	return nil
}
