package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type fakeMaterialStore struct {
	decisions []vulnerability.StandingDecision
	checked   []shared.ID
}

func (s *fakeMaterialStore) ListStandingDecisions(context.Context, int) ([]vulnerability.StandingDecision, error) {
	return s.decisions, nil
}
func (s *fakeMaterialStore) SetBaseline(context.Context, vulnerability.StandingDecision, approvalpolicy.Facts) error {
	return nil
}
func (s *fakeMaterialStore) MarkChecked(_ context.Context, d vulnerability.StandingDecision) error {
	s.checked = append(s.checked, d.ApprovalID)
	return nil
}
func (s *fakeMaterialStore) EndAcceptance(context.Context, vulnerability.StandingDecision, []approvalpolicy.Signal, *time.Time, time.Time) (bool, error) {
	return false, errors.New("boom")
}
func (s *fakeMaterialStore) FlagDecision(context.Context, vulnerability.StandingDecision, string, []approvalpolicy.Signal) (bool, error) {
	return false, errors.New("boom")
}
func (s *fakeMaterialStore) RevokeFalsePositive(context.Context, vulnerability.StandingDecision, []approvalpolicy.Signal, *time.Time, time.Time) (bool, error) {
	return false, errors.New("boom")
}

type failingPolicies struct{}

func (failingPolicies) EffectiveApprovalPolicy(context.Context, shared.ID) (approvalpolicy.Policy, error) {
	return approvalpolicy.Policy{}, errors.New("policy unavailable")
}

// Every decision looked at is marked checked, a failed one too: otherwise a
// decision that always fails stays first in line and holds the batch.
func TestApprovalMaterialChange_MarksEveryAttemptChecked(t *testing.T) {
	base := approvalpolicy.Facts{Severity: "low"}
	mk := func() vulnerability.StandingDecision {
		return vulnerability.StandingDecision{ApprovalID: shared.NewID(), TenantID: shared.NewID(), FindingID: shared.NewID(),
			Status: vulnerability.FindingStatusAccepted, Baseline: &base, Current: approvalpolicy.Facts{Severity: "critical"}}
	}
	store := &fakeMaterialStore{decisions: []vulnerability.StandingDecision{mk(), mk()}}
	c := NewApprovalMaterialChangeController(store, failingPolicies{}, nil, nil, 0, 10, nil)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.checked) != 2 {
		t.Fatalf("marked %d of 2 decisions checked after a failure", len(store.checked))
	}
}
