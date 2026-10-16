package jira

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A Jira webhook has no person behind it who holds findings:verify or an
// approval, so no mapping (default or tenant overlay) may close a finding.

var closingTargets = []string{"resolved", "false_positive", "accepted", "duplicate"} //nolint:gochecknoglobals // fixture

func TestParseMappingConfig_DropsClosingInboundTargets(t *testing.T) {
	inbound := map[string]any{"Shipped": "fix_applied"}
	for i, target := range closingTargets {
		inbound[[]string{"Done", "Won't Do", "Accepted", "Dup"}[i]] = target
	}
	m := ParseMappingConfig(map[string]any{"ticketing": map[string]any{"status_inbound": inbound}})
	// "Done" keeps its safe default (fix_applied); the others are unmapped.
	if s, ok := m.FindingStatusForJira("Done"); !ok || s != vulnerability.FindingStatusFixApplied {
		t.Errorf("Done = (%q,%v), want the default fix_applied, not the resolved overlay", s, ok)
	}
	for _, js := range []string{"Won't Do", "Accepted", "Dup"} {
		if s, ok := m.FindingStatusForJira(js); ok {
			t.Errorf("%s mapped to %q; a closing overlay must be dropped", js, s)
		}
	}
	if s, ok := m.FindingStatusForJira("shipped"); !ok || s != vulnerability.FindingStatusFixApplied {
		t.Errorf("a safe sibling overlay must still apply: (%q,%v)", s, ok)
	}
}

func TestValidateTicketingConfig(t *testing.T) {
	ok := map[string]any{"ticketing": map[string]any{"status_inbound": map[string]any{
		"Shipped": "fix_applied", "QA": "in_progress", "Reopened": "confirmed",
	}}}
	if err := ValidateTicketingConfig(ok); err != nil {
		t.Fatalf("safe inbound map refused: %v", err)
	}
	if err := ValidateTicketingConfig(map[string]any{"other": 1}); err != nil {
		t.Fatalf("config without ticketing refused: %v", err)
	}
	for _, target := range append(closingTargets, "not_a_status") {
		cfg := map[string]any{"ticketing": map[string]any{"status_inbound": map[string]any{"Done": target}}}
		if err := ValidateTicketingConfig(cfg); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("status_inbound Done=%q: err = %v, want ErrValidation", target, err)
		}
	}
	bad := map[string]any{"ticketing": map[string]any{"status_inbound": "done=resolved"}}
	if err := ValidateTicketingConfig(bad); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("non-object status_inbound: err = %v, want ErrValidation", err)
	}
}

type inboundRepo struct {
	vulnerability.FindingRepository
	finding *vulnerability.Finding
	updates int
}

func (r *inboundRepo) GetByWorkItemURI(_ context.Context, _ shared.ID, _ string) (*vulnerability.Finding, error) {
	return r.finding, nil
}

func (r *inboundRepo) Update(_ context.Context, _ *vulnerability.Finding) error {
	r.updates++
	return nil
}

type recordedChange struct{ old, new, integration, ref string }

type activityStub struct{ got []recordedChange }

func (a *activityStub) RecordIntegrationStatusChange(_ context.Context, _, _ shared.ID, oldS, newS, integ, ref string) error {
	a.got = append(a.got, recordedChange{oldS, newS, integ, ref})
	return nil
}

func inProgressFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f := buildFinding(t, "https://x.atlassian.net/browse/SEC-1")
	for _, st := range []vulnerability.FindingStatus{vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusInProgress} {
		if err := f.TransitionStatus(st, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func doneWebhook() WebhookPayload {
	return WebhookPayload{
		Issue:     WebhookIssue{Key: "SEC-1", Self: "https://x.atlassian.net/rest/api/2/issue/10001"},
		Changelog: &Changelog{Items: []ChangeItem{{Field: "status", FromString: "In Progress", ToString: "Done"}}},
	}
}

// Even a mapping that was built around ParseMappingConfig (an old stored row,
// a future code path) cannot make "Done" resolve the finding.
func TestHandleJiraWebhook_ClosingMappingNeverApplied(t *testing.T) {
	for _, target := range closingTargets {
		// confirmed -> every closing target is a legal domain transition, so
		// only the inbound gate stops it.
		f := buildFinding(t, "https://x.atlassian.net/browse/SEC-1")
		if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil); err != nil {
			t.Fatal(err)
		}
		repo := &inboundRepo{finding: f}
		act := &activityStub{}
		s := NewSyncService(repo, nil, logger.NewNop())
		m := DefaultMappingConfig()
		m.StatusInbound["done"] = vulnerability.FindingStatus(target)
		s.SetMappingResolver(stubMappingResolver{mapping: m})
		s.SetActivityRecorder(act)

		if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), doneWebhook()); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if st := repo.finding.Status(); st != vulnerability.FindingStatusConfirmed || repo.updates != 0 || len(act.got) != 0 {
			t.Errorf("Done mapped to %s moved the finding to %s (%d updates), want unchanged", target, st, repo.updates)
		}
	}
}

type applierStub struct {
	ids    []shared.ID
	target vulnerability.FindingStatus
	ref    string
}

func (a *applierStub) ApplyTicketStatus(_ context.Context, _ shared.ID, ids []shared.ID, target vulnerability.FindingStatus, _, ref, _ string) ([]shared.ID, []InboundRefusal, error) {
	a.ids, a.target, a.ref = ids, target, ref
	return ids, nil, nil
}

// The safe path goes through the finding service (the applier), with the
// tenant overlay's target, and never writes the finding row itself.
func TestHandleJiraWebhook_GoesThroughTheServicePath(t *testing.T) {
	repo := &inboundRepo{finding: inProgressFinding(t)}
	s := NewSyncService(repo, nil, logger.NewNop())
	m := DefaultMappingConfig()
	m.StatusInbound["done"] = vulnerability.FindingStatusFixApplied
	s.SetMappingResolver(stubMappingResolver{mapping: m})
	app := &applierStub{}
	s.SetInboundApplier(app)

	if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), doneWebhook()); err != nil {
		t.Fatal(err)
	}
	if app.target != vulnerability.FindingStatusFixApplied || len(app.ids) != 1 || app.ids[0] != repo.finding.ID() || app.ref != "SEC-1" {
		t.Fatalf("applier got %+v, want the linked finding claimed fix_applied from SEC-1", app)
	}
	if repo.updates != 0 {
		t.Fatalf("the sync service wrote the finding row itself (%d updates)", repo.updates)
	}
}

// Without the service path wired, nothing is applied (fail closed).
func TestHandleJiraWebhook_NoApplierAppliesNothing(t *testing.T) {
	repo := &inboundRepo{finding: inProgressFinding(t)}
	s := NewSyncService(repo, nil, logger.NewNop())
	if err := s.HandleJiraWebhook(context.Background(), shared.NewID(), doneWebhook()); err != nil {
		t.Fatal(err)
	}
	if repo.finding.Status() != vulnerability.FindingStatusInProgress || repo.updates != 0 {
		t.Fatalf("status = %s (%d updates), want unchanged", repo.finding.Status(), repo.updates)
	}
}
