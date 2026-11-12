package retest

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/closuremode"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The organization's closing mode in front of the retest's own close
// (docs/architecture/finding-verification-plan.md, "Closing mode"). A
// confirmed fix resolves a finding only when the tenant opted in
// (settings.retest.auto_resolve) AND the closing mode closes a verified
// retest (method retest_verified): auto closes, review records a Ready to
// close proposal, off keeps the finding open and proposes nothing.

// Closing-mode decisions written on the retest_completed activity.
const (
	closureDecisionClose   = "close"
	closureDecisionPropose = "propose"
	closureDecisionKeep    = "keep"
)

// SetClosureSettings wires the organization closing policy (the tenant
// service). Without it every organization is in review: a confirmed fix
// proposes and closes nothing.
func (s *Service) SetClosureSettings(r closuremode.SettingsReader) { s.closure = r }

// closureDecision is what the closing mode lets a confirmed fix do to the
// finding: close, propose or keep. The policy read is tenant-scoped; an id
// the tenant-scoped tier read does not return is kept.
func (s *Service) closureDecision(ctx context.Context, tenantID, findingID shared.ID) string {
	d := closuremode.Decider{Settings: s.closure, Repo: s.findings, Log: s.logger}
	closeIDs, propose, _ := d.Split(ctx, tenantID, []shared.ID{findingID}, vulnerability.ClosureMethodRetestVerified)
	switch {
	case len(closeIDs) == 1:
		return closureDecisionClose
	case len(propose) == 1:
		return closureDecisionPropose
	default:
		return closureDecisionKeep
	}
}

// proposeFix records a Ready to close proposal (method retest_verified) for
// the confirmed fix, with the retest as its evidence. The record only lands
// while the finding is still in an open status (the repository re-checks).
func (s *Service) proposeFix(ctx context.Context, rt *retestdom.Retest, checkedAt time.Time) {
	evidence := map[string]any{
		"retest_id": rt.ID.String(), "trigger": string(rt.Trigger), "template_id": rt.TemplateID, "target": rt.Target,
		"observed_at": checkedAt.UTC().Format(time.RFC3339),
	}
	if rt.Method != "" {
		evidence["method"] = rt.Method
	}
	if rt.SensorID != nil {
		evidence["sensor_ids"] = []string{rt.SensorID.String()}
	}
	rec := vulnerability.ClosureProposalRecord{
		FindingID: rt.FindingID, Method: vulnerability.ClosureMethodRetestVerified, Evidence: evidence, EvidenceAt: checkedAt,
	}
	if rt.CheckCommandID != nil {
		rec.CommandID = *rt.CheckCommandID
		evidence["command_id"] = rt.CheckCommandID.String()
	}
	d := closuremode.Decider{Settings: s.closure, Repo: s.findings, Log: s.logger}
	d.Record(ctx, rt.TenantID, []vulnerability.ClosureProposalRecord{rec})
}
