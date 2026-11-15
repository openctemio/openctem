package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreport"
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
	// noticed: the commands that have the held-critical notice.
	noticed map[shared.ID]bool
	// release: what ReleaseRunFindings returns; releaseCalls its calls.
	release      []shared.ID
	releaseCalls int
	releaseHosts []string
	// loaded: what GetByIDs returns.
	loaded []*vulnerability.Finding
}

func (f *fakeHolder) OnceHeldNotice(_ context.Context, _, commandID shared.ID, _ string, send func(*sql.Tx) error) (bool, error) {
	if f.noticed == nil {
		f.noticed = map[shared.ID]bool{}
	}
	if f.noticed[commandID] {
		return false, nil
	}
	if err := send(nil); err != nil {
		return false, err
	}
	f.noticed[commandID] = true
	return true, nil
}

func (f *fakeHolder) ReleaseRunFindings(_ context.Context, tenantID, commandID shared.ID, hosts, reasons []string) ([]shared.ID, error) {
	f.releaseCalls++
	f.tenant, f.command, f.releaseHosts, f.reasons = tenantID, commandID, hosts, reasons
	return f.release, nil
}

func (f *fakeHolder) GetByIDs(_ context.Context, _ shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error) {
	var out []*vulnerability.Finding
	for _, x := range f.loaded {
		if slices.Contains(ids, x.ID()) {
			out = append(out, x)
		}
	}
	return out, nil
}

func (f *fakeHolder) HoldGapFindings(_ context.Context, tenantID, commandID shared.ID, reportID string, hosts, reasons []string) ([]vulnerability.HeldFinding, error) {
	f.calls++
	f.tenant, f.command, f.report, f.hosts, f.reasons = tenantID, commandID, reportID, hosts, reasons
	return f.held, nil
}

type fakeOutbox struct{ sent []outbox.EnqueueParams }

func (o *fakeOutbox) EnqueueInTx(_ context.Context, _ *sql.Tx, p outbox.EnqueueParams) error {
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

	if n.AggregateID == nil || n.AggregateID.String() != cmd.String() {
		t.Fatalf("notice not keyed on the command: %+v", n.AggregateID)
	}

	// Another report of the same command (or its evaluation) holds more
	// criticals: still the one notice per command.
	repo.held = []vulnerability.HeldFinding{{ID: shared.NewID(), Severity: "critical"}}
	s.holdRunFindings(context.Background(), tenant, cmd, json.RawMessage(throttledResult), "r2")
	s.holdRunFindings(context.Background(), tenant, cmd, json.RawMessage(throttledResult), "")
	if len(ob.sent) != 1 {
		t.Fatalf("notices for one command %d, want one", len(ob.sent))
	}
	// Another command sends its own.
	s.holdRunFindings(context.Background(), tenant, shared.NewID(), json.RawMessage(throttledResult), "")
	if len(ob.sent) != 2 {
		t.Fatalf("notices for two commands %d, want two", len(ob.sent))
	}

	// No critical among the held: no notice.
	repo.held, ob.sent = []vulnerability.HeldFinding{{ID: high, Severity: "high"}}, nil
	s.holdRunFindings(context.Background(), tenant, shared.NewID(), json.RawMessage(throttledResult), "")
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

func TestResultGapHostsComplete(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		hosts    []string
		complete bool
	}{
		{"no result", ``, nil, false},
		{"unreadable", `{"metadata":`, nil, false},
		{"no gaps", `{"metadata":{}}`, nil, true},
		{"empty list", `{"metadata":{"coverage_gaps":[],"coverage_gaps_total":0}}`, nil, true},
		{"total without the list", `{"metadata":{"coverage_gaps_total":3}}`, nil, false},
		{"whole list", throttledResult, []string{"a.example.com"}, true},
		{"non-holding gap only", `{"metadata":{"coverage_gaps":[{"host":"b.example.com","reason":"breaker_open"}],"coverage_gaps_total":1}}`, nil, true},
		{"cut list", `{"metadata":{"coverage_gaps":[{"host":"a.example.com","reason":"throttled"}],"coverage_gaps_total":40}}`, []string{"a.example.com"}, false},
		{"unknown reason", `{"metadata":{"coverage_gaps":[{"host":"a.example.com","reason":"some_new_reason"}],"coverage_gaps_total":1}}`, nil, false},
	} {
		hosts, complete := resultGapHosts(json.RawMessage(tc.raw))
		if !slices.Equal(hosts, tc.hosts) || complete != tc.complete {
			t.Errorf("%s: %v %v, want %v %v", tc.name, hosts, complete, tc.hosts, tc.complete)
		}
	}
}

// A completed run whose result lists every gap releases the held findings
// it saw again on its clean hosts and announces them once; a run that did
// not complete, stopped early or cut its gap list releases nothing.
func TestReleaseRunFindings(t *testing.T) {
	tenant, cmd := shared.NewID(), shared.NewID()
	mk := func(st vulnerability.FindingStatus) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceDAST, "nuclei", vulnerability.SeverityCritical, "m")
		if err != nil {
			t.Fatal(err)
		}
		if st != "" {
			if err := f.ApplyPlatformTransition(st, "checked"); err != nil {
				t.Fatal(err)
			}
		}
		return f
	}
	released, decided, closed := mk(""), mk(vulnerability.FindingStatusFalsePositive), mk(vulnerability.FindingStatusResolved)
	stillHeld := mk("")
	stillHeld.Hold(vulnerability.HoldTargetThrottled)
	repo := &fakeHolder{
		release: []shared.ID{released.ID(), decided.ID(), closed.ID(), stillHeld.ID()},
		loaded:  []*vulnerability.Finding{released, decided, closed, stillHeld},
	}
	var announced [][]*vulnerability.Finding
	p := &FindingProcessor{repo: repo, logger: logger.NewNop(),
		findingCreatedCallback: func(_ context.Context, _ shared.ID, fs []*vulnerability.Finding) { announced = append(announced, fs) }}
	s := &Service{logger: logger.NewNop(), findingRepo: repo, findingProcessor: p}
	cov := func(status, result string) *ingestreport.CommandCoverage {
		return &ingestreport.CommandCoverage{CommandType: "scan", CommandStatus: status, Result: json.RawMessage(result)}
	}

	for name, c := range map[string]*ingestreport.CommandCoverage{
		"running":   cov("running", `{"metadata":{}}`),
		"no result": cov("completed", ``),
		"cut list":  cov("completed", `{"metadata":{"coverage_gaps":[{"host":"a.example.com","reason":"throttled"}],"coverage_gaps_total":9}}`),
		"stopped":   cov("completed", `{"exit_code":137,"metadata":{}}`),
	} {
		if got := s.releaseRunFindings(context.Background(), tenant, cmd, c); got != nil || repo.releaseCalls != 0 {
			t.Fatalf("%s: released %v (%d calls)", name, got, repo.releaseCalls)
		}
	}

	// No gaps: every host is clean.
	got := s.releaseRunFindings(context.Background(), tenant, cmd, cov("completed", `{"metadata":{}}`))
	if len(got) != 4 || repo.releaseCalls != 1 || repo.tenant != tenant || repo.command != cmd || len(repo.releaseHosts) != 0 ||
		!slices.Equal(repo.reasons, []string{vulnerability.HoldTargetThrottled}) {
		t.Fatalf("release call %+v, got %v", repo, got)
	}
	// Only the open, undecided, no longer held finding is announced.
	if len(announced) != 1 || len(announced[0]) != 1 || announced[0][0] != released {
		t.Fatalf("announced %v, want only the released open finding", announced)
	}

	// Gaps: the throttled hosts are passed to the repository to keep held.
	repo.release, announced = nil, nil
	s.releaseRunFindings(context.Background(), tenant, cmd, cov("completed", throttledResult))
	if !slices.Equal(repo.releaseHosts, []string{"a.example.com"}) || announced != nil {
		t.Fatalf("hosts %v, announced %v", repo.releaseHosts, announced)
	}
}
