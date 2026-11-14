package ingest

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func TestResultHoldHosts(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{
		{"none", ``, nil},
		{"no gaps", `{"metadata":{}}`, nil},
		{"unreadable", `{"metadata":`, nil},
		{"throttling reasons only, normalised, once each", `{"metadata":{"coverage_gaps":[
			{"host":"A.example.com:443","reason":"throttled"},
			{"host":"https://a.example.com","reason":"blocked"},
			{"host":"b.example.com","reason":"rate_floor"},
			{"host":"c.example.com","reason":"breaker_open"},
			{"host":"d.example.com","reason":"proxy_unavailable"},
			{"host":"e.example.com","reason":"edge_protected"},
			{"host":"f.example.com","reason":"catch_all"},
			{"host":"192.0.2.10:8080","reason":"throttled"}
		],"coverage_gaps_total":8}}`, []string{"a.example.com", "b.example.com", "e.example.com", "f.example.com", "192.0.2.10"}},
	} {
		got := resultHoldHosts(json.RawMessage(tc.raw))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

type fakeHolder struct {
	vulnerability.FindingRepository
	calls           int
	tenant, command shared.ID
	report          string
	hosts, reasons  []string
	held            []vulnerability.HeldFinding
}

func (f *fakeHolder) HoldGapFindings(_ context.Context, tenantID, commandID shared.ID, reportID string, hosts, reasons []string) ([]vulnerability.HeldFinding, error) {
	f.calls++
	f.tenant, f.command, f.report, f.hosts, f.reasons = tenantID, commandID, reportID, hosts, reasons
	return f.held, nil
}

type fakeOutbox struct{ sent []outbox.EnqueueParams }

func (o *fakeOutbox) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	o.sent = append(o.sent, p)
	return nil
}

const throttledResult = `{"metadata":{"coverage_gaps":[{"host":"a.example.com","reason":"throttled"}],"coverage_gaps_total":1}}`

// A throttled run holds its findings on the throttled host and sends one
// notice for the held critical ones; a run without such a gap does nothing.
func TestHoldRunFindings(t *testing.T) {
	tenant, cmd := shared.NewID(), shared.NewID()
	crit1, crit2, high := shared.NewID(), shared.NewID(), shared.NewID()
	repo := &fakeHolder{held: []vulnerability.HeldFinding{{ID: crit1, Severity: "critical"}, {ID: crit2, Severity: "critical"}, {ID: high, Severity: "high"}}}
	ob := &fakeOutbox{}
	s := &Service{logger: logger.NewNop(), findingRepo: repo, heldOutbox: ob}

	got := s.holdRunFindings(context.Background(), tenant, cmd, json.RawMessage(throttledResult), "r1")
	if len(got) != 3 || repo.tenant != tenant || repo.command != cmd || repo.report != "r1" ||
		!slices.Equal(repo.hosts, []string{"a.example.com"}) || !slices.Equal(repo.reasons, []string{vulnerability.HoldTargetThrottled}) {
		t.Fatalf("hold call %+v, got %v", repo, got)
	}
	if len(ob.sent) != 1 {
		t.Fatalf("notices %d, want one", len(ob.sent))
	}
	n := ob.sent[0]
	if n.TenantID != tenant || n.EventType != string(integration.EventTypeFindingHeldCritical) || n.Severity != "critical" || n.Metadata["held_critical"] != 2 {
		t.Fatalf("notice %+v", n)
	}

	// No critical among the held: no notice.
	repo.held, ob.sent = []vulnerability.HeldFinding{{ID: high, Severity: "high"}}, nil
	s.holdRunFindings(context.Background(), tenant, cmd, json.RawMessage(throttledResult), "")
	if len(ob.sent) != 0 {
		t.Fatalf("notice without a held critical: %+v", ob.sent)
	}
	// No throttling gap: the repository is not even asked.
	repo.calls = 0
	s.holdRunFindings(context.Background(), tenant, cmd, json.RawMessage(`{"metadata":{"coverage_gaps":[{"host":"a.example.com","reason":"breaker_open"}]}}`), "")
	if repo.calls != 0 {
		t.Fatal("held findings without a throttling gap")
	}
}

// Held findings send no created event; the others do.
func TestApplyRunHoldAndWithoutHeld(t *testing.T) {
	tenant := shared.NewID()
	mk := func() *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceDAST, "nuclei", vulnerability.SeverityCritical, "m")
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	a, b := mk(), mk()
	ctx := context.WithValue(context.Background(), runHoldKey{}, runHold(func(context.Context, shared.ID) []vulnerability.HeldFinding {
		return []vulnerability.HeldFinding{{ID: a.ID(), Severity: "critical"}}
	}))
	created := []*vulnerability.Finding{a, b}
	applyRunHold(ctx, tenant, created)
	if !a.IsHeld() || b.IsHeld() {
		t.Fatalf("held a=%v b=%v", a.IsHeld(), b.IsHeld())
	}
	if out := withoutHeld(created); len(out) != 1 || out[0] != b {
		t.Fatalf("withoutHeld %v", out)
	}
	// No run hold in the context: nothing changes.
	c := mk()
	applyRunHold(context.Background(), tenant, []*vulnerability.Finding{c})
	if c.IsHeld() {
		t.Fatal("held without a run hold")
	}
}
