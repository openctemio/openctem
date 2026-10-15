package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Service paths that change a finding status follow the lifecycle.

func lifecycleFindingAt(t *testing.T, path ...vulnerability.FindingStatus) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, "m")
	require.NoError(t, err)
	for _, s := range path {
		require.NoError(t, f.TransitionStatus(s, "", nil))
	}
	return f
}

// A fix_applied finding cannot be requested as a false positive: that is not a
// lifecycle move (it goes back to in_progress, or is verified and resolved).
func TestLifecycle_RequestApprovalRefusesIllegalMove(t *testing.T) {
	repo := newMockFindingRepository()
	id := shared.NewID()
	repo.findings[id] = lifecycleFindingAt(t, vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress, vulnerability.FindingStatusFixApplied)
	svc := newApprovalTestService(repo, newMockApprovalRepository())

	_, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID: shared.NewID().String(), FindingID: id.String(), RequestedStatus: "false_positive",
		Justification: "not real", RequestedBy: shared.NewID().String(),
	})
	require.ErrorIs(t, err, shared.ErrValidation)
}

// The finding moved after the request: approving it no longer applies a
// lifecycle move, so it is refused and nothing is written.
func TestLifecycle_ApproveStatusRefusesWhenFindingMoved(t *testing.T) {
	repo := newMockFindingRepository()
	approvals := newMockApprovalRepository()
	id := shared.NewID()
	f := lifecycleFindingAt(t, vulnerability.FindingStatusConfirmed)
	repo.findings[id] = f
	svc := newApprovalTestService(repo, approvals)
	tenant := shared.NewID()

	a, err := svc.RequestApproval(context.Background(), finding.RequestApprovalInput{
		TenantID: tenant.String(), FindingID: id.String(), RequestedStatus: "false_positive",
		Justification: "not real", RequestedBy: shared.NewID().String(),
	})
	require.NoError(t, err)
	require.NoError(t, f.TransitionStatus(vulnerability.FindingStatusInProgress, "", nil))

	_, err = svc.ApproveStatus(context.Background(), finding.ApproveStatusInput{
		TenantID: tenant.String(), ApprovalID: a.ID.String(), ApprovedBy: shared.NewID().String(),
	})
	require.ErrorIs(t, err, shared.ErrValidation)
	require.Empty(t, repo.statusUpdates)
	require.Equal(t, vulnerability.ApprovalStatusPending, approvals.approvals[a.ID].Status)
}

// Triage confirms a finding only where the lifecycle allows it.
func TestLifecycle_TriageFindingRefusesIllegalMove(t *testing.T) {
	repo := newMockFindingRepository()
	id := shared.NewID()
	f := lifecycleFindingAt(t, vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress, vulnerability.FindingStatusFixApplied)
	repo.findings[id] = f
	svc := newApprovalTestService(repo, newMockApprovalRepository())

	_, err := svc.TriageFinding(context.Background(), id.String(), f.TenantID().String(), shared.NewID().String(), "")
	require.Error(t, err)
	require.True(t, errors.Is(err, shared.ErrValidation), "got %v", err)
	require.Equal(t, vulnerability.FindingStatusFixApplied, f.Status())
}

// An expired acceptance reopening only a still-accepted finding is covered
// against the database in tests/integration/finding_acceptance_expiry_atomic_test.go.

// The retired aliases are not statuses: a status change to one is a 400
// (validation), never mapped to the canonical status.
func TestLifecycle_AliasStatusesAreRefused(t *testing.T) {
	for _, alias := range []string{"accepted_risk", "verified", "remediation", "retest", "open"} {
		svc, _, _ := newVulnTestService()
		tenantID := shared.NewID()
		created := createTestFindingViaService(t, svc, tenantID.String())
		_, err := svc.UpdateFindingStatus(context.Background(), created.ID().String(), tenantID.String(),
			finding.UpdateFindingStatusInput{Status: alias, HasVerifyPermission: true})
		require.ErrorIs(t, err, shared.ErrValidation, alias)

		_, err = svc.ListFindings(context.Background(), finding.ListFindingsInput{TenantID: tenantID.String(), Statuses: []string{alias}})
		require.ErrorIs(t, err, shared.ErrValidation, "list filter %s", alias)
	}
}
