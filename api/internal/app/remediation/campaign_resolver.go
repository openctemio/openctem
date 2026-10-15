package remediation

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// CampaignFilterResolver adapts the finding bulk-status path + abuse guard to
// exposure.CampaignFindingResolver: a campaign resolve marks the open findings
// of its filter fixed (in the caller's data scope). Kept here (not in
// exposure) so exposure needn't import the finding service or the guard.
type CampaignFilterResolver struct {
	vuln  *finding.VulnerabilityService
	guard *finding.BulkGuard
}

// NewCampaignFilterResolver wires the resolver; guard may be nil (no abuse gate).
func NewCampaignFilterResolver(vuln *finding.VulnerabilityService, guard *finding.BulkGuard) CampaignFilterResolver {
	return CampaignFilterResolver{vuln: vuln, guard: guard}
}

// maxCampaignResolve caps how many findings one campaign-resolve touches; the
// abuse guard still enforces the tenant ceiling / hourly budget within this.
const maxCampaignResolve = 2000

// ResolveOpenByFilter marks the open findings of the filter that the caller
// may see fixed, through the guarded bulk path.
func (a CampaignFilterResolver) ResolveOpenByFilter(ctx context.Context, tenantID string, filter vulnerability.FindingFilter, in exposure.CampaignResolveInput) (*exposure.CampaignResolveResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, err
	}
	filter.ExcludeStatuses = vulnerability.ClosedFindingStatuses()
	ids, err := a.vuln.ListFindingIDs(ctx, filter, maxCampaignResolve)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return &exposure.CampaignResolveResult{}, nil
	}
	if a.guard != nil {
		if err := a.guard.CheckBulk(ctx, tid, len(ids), in.Approved); err != nil {
			return nil, err
		}
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	status := in.Status
	if status == "" {
		status = string(vulnerability.FindingStatusFixApplied)
	}
	res, err := a.vuln.BulkUpdateFindingsStatus(ctx, tenantID, finding.BulkUpdateStatusInput{
		FindingIDs:            idStrs,
		Status:                status,
		Resolution:            in.Resolution,
		ActorID:               in.ActorID,
		HasVerifyPermission:   in.HasVerifyPermission,
		HasFixApplyPermission: in.HasFixApplyPermission,
		WalkToFixApplied:      true,
	})
	if err != nil {
		return nil, err
	}
	return CampaignResolveResult(res), nil
}

// CampaignResolveResult carries the bulk path's outcome, with the reason for
// every finding not updated, to the campaign resolve response.
func CampaignResolveResult(res *finding.BulkUpdateResult) *exposure.CampaignResolveResult {
	out := &exposure.CampaignResolveResult{
		Updated: res.Updated, Skipped: res.Skipped, Failed: res.Failed,
		ValidationsQueued: res.ValidationsQueued,
		Rows:              make([]exposure.CampaignResolveRow, 0, len(res.Rows)),
	}
	for _, r := range res.Rows {
		out.Rows = append(out.Rows, exposure.CampaignResolveRow{FindingID: r.FindingID, Outcome: r.Outcome, Reason: r.Reason})
	}
	return out
}
