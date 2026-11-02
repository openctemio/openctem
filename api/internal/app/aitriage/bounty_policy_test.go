package aitriage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type countingDispatcher struct{ completed int }

func (d *countingDispatcher) DispatchAITriageCompleted(context.Context, shared.ID, shared.ID, shared.ID, map[string]any) {
	d.completed++
}
func (d *countingDispatcher) DispatchAITriageFailed(context.Context, shared.ID, shared.ID, shared.ID, string) {
}

type countingProposer struct{ n int }

func (p *countingProposer) ProposeFalsePositiveFromAI(context.Context, shared.ID, shared.ID, float64, string) (bool, error) {
	p.n++
	return true, nil
}

// fpTriageJSON is a confident false-positive verdict (a proposal for any
// other finding).
const fpTriageJSON = `{"severity_assessment":"high","severity_justification":"j","risk_score":50,
"exploitability":"medium","exploitability_details":"d","business_impact":"b","false_positive_likelihood":0.95,
"false_positive_reason":"r","priority_rank":50,"remediation_steps":[],"related_cves":[],"related_cwes":[],"summary":"s"}`

// A bug-bounty report reaches the model only when a person asks: no
// auto-triage, no workflow action or request without a user, no bulk
// without a user, and a row queued without a person is failed by the worker.
func TestAITriage_BugBounty_PersonRequestOnly(t *testing.T) {
	ctx := context.Background()
	h := newEgressHarness(t)
	f := h.finding(t, vulnerability.FindingSourceBugBounty, nil)
	tid := h.tenantID.String()

	// Workflow action / request without a user.
	_, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: tid, FindingID: f.ID().String(), TriageType: "manual"})
	require.ErrorIs(t, err, ErrPersonRequestOnly)
	require.ErrorIs(t, err, ErrPolicyRestricted)

	// Bulk without a user.
	bulk, err := h.svc.RequestBulkTriage(ctx, BulkTriageRequest{TenantID: tid, FindingIDs: []string{f.ID().String()}})
	require.NoError(t, err)
	require.Equal(t, 1, bulk.Failed)
	require.Equal(t, FailPolicyRestricted, bulk.Jobs[0].Error)

	// Auto-triage: silently not queued.
	require.NoError(t, h.svc.EnqueueAutoTriage(ctx, h.tenantID, f.ID()))
	require.Zero(t, h.triage.created, "no triage row for an unrequested bug-bounty report")
	require.Zero(t, h.enqueuer.n, "no job for an unrequested bug-bounty report")

	// Worker: a row queued without a person is failed before the call.
	row := h.pendingRow(t, f)
	err = h.svc.ProcessTriage(aitriagedom.WithRetriesLeft(ctx, true), row.ID(), h.tenantID, f.ID())
	require.ErrorIs(t, err, aitriagedom.ErrTriageFailed)
	require.Equal(t, FailPolicyRestricted, row.ErrorMessage())
	require.Zero(t, h.llm.calls, "the model must never see an unrequested bug-bounty report")
}

// A person may ask, alone or in bulk; the verdict then starts nothing on its
// own (no false-positive proposal, no workflow event), while the same
// verdict on a scanner finding does.
func TestAITriage_BugBounty_PersonRequestNoFollowUps(t *testing.T) {
	ctx := context.Background()
	h := newEgressHarness(t)
	h.llm.resp = fpTriageJSON
	disp, prop := &countingDispatcher{}, &countingProposer{}
	h.svc.SetWorkflowDispatcher(disp)
	h.svc.SetFalsePositiveProposer(prop)
	// Auto-apply, so a scanner verdict would file a request on its own.
	h.svc.SetUseCases(fakeUseCases{set: autoApply()})
	user := shared.NewID().String()
	tid := h.tenantID.String()

	report := h.finding(t, vulnerability.FindingSourceBugBounty, nil)
	resp, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: tid, FindingID: report.ID().String(), TriageType: "manual", UserID: &user})
	require.NoError(t, err)
	rid := shared.MustIDFromString(resp.JobID)
	require.NoError(t, h.svc.ProcessTriage(ctx, rid, h.tenantID, report.ID()))
	require.Equal(t, aitriagedom.TriageStatusCompleted, h.triage.rows[rid].Status())
	require.Equal(t, 1, h.llm.calls)
	require.Zero(t, prop.n, "no false-positive proposal from a bug-bounty verdict")
	require.Zero(t, disp.completed, "no workflow event from a bug-bounty verdict")

	bulk, err := h.svc.RequestBulkTriage(ctx, BulkTriageRequest{TenantID: tid, FindingIDs: []string{report.ID().String()}, UserID: &user})
	require.NoError(t, err)
	require.Equal(t, 1, bulk.Queued)

	scanner := h.finding(t, vulnerability.FindingSourceDAST, nil)
	resp, err = h.svc.RequestTriage(ctx, TriageRequest{TenantID: tid, FindingID: scanner.ID().String(), TriageType: "manual"})
	require.NoError(t, err)
	require.NoError(t, h.svc.ProcessTriage(ctx, shared.MustIDFromString(resp.JobID), h.tenantID, scanner.ID()))
	require.Equal(t, 1, disp.completed, "a scanner verdict still reaches workflows")
	require.Equal(t, 1, prop.n, "a scanner verdict files a false-positive request in auto-apply")
}
