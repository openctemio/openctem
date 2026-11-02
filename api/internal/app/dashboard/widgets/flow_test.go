package widgets

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func flowFacts() *ctemFacts {
	hour := time.Hour
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	return &ctemFacts{
		breached: 43, within: 60, slaDen: 100,
		byClass: []dashboard.CountRow{{Keys: []string{"P0"}, Count: 9}, {Keys: []string{"P1"}, Count: 82},
			{Keys: []string{"P2"}, Count: 260}, {Keys: []string{"P3"}, Count: 440}, {Keys: []string{"none"}, Count: 5}},
		bySev: []dashboard.CountRow{{Keys: []string{"low"}, Count: 220}, {Keys: []string{"critical"}, Count: 41},
			{Keys: []string{"high"}, Count: 150}, {Keys: []string{"medium"}, Count: 385}, {Keys: []string{"info"}, Count: 0}},
		outcomes: dashboard.OutcomeCounts{InProgress: 112, Fixed: 318, Accepted: 22, FalsePositive: 97},
		intake: []dashboard.IntakeRow{
			// Healthy: every hour, last one 30 minutes ago.
			{Origin: "sensor", Tool: "nuclei", Receipts: 30, Received: 402, Created: 88, StillDetected: 300, Reopened: 4,
				Skipped: 6, Failed: 0, Suppressed: 8, LastAt: now.Add(-30 * time.Minute), LastStatus: "completed",
				LastReceiptID: shared.NewID(), MedianGap: &hour},
			// Stale: usually hourly, nothing for 3 days.
			{Origin: "connector", Tool: "cloud", Receipts: 10, Received: 173, Created: 52, StillDetected: 113, Reopened: 0,
				Skipped: 8, LastAt: now.Add(-72 * time.Hour), LastStatus: "completed", LastReceiptID: shared.NewID(), MedianGap: &hour},
			// Failed: the latest receipt failed.
			{Origin: "ci", Tool: "unknown", Receipts: 2, Received: 27, Created: 4, StillDetected: 19, Failed: 4,
				LastAt: now.Add(-2 * time.Hour), LastStatus: "failed", LastReceiptID: shared.NewID()},
		},
	}
}

func fixedNow(s *Service) time.Time {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return now
}

func TestExposureFlow_OrganizationRead(t *testing.T) {
	facts := flowFacts()
	s := NewService(nil, nil, facts, nil)
	now := fixedNow(s)
	scope := orgScope(shared.NewID())
	v := s.widget(context.Background(), 0, ctemWidget("exposure.flow", "flow", 0), true, scope)
	if v.State != StateReady || v.Shape != dashboard.ShapeFlow || v.Flow == nil {
		t.Fatalf("state %s reason %s shape %s flow %v", v.State, v.Reason, v.Shape, v.Flow)
	}
	f := v.Flow
	// Actionable is P0 to P3 (the unclassified are open but not in the ring).
	if f.Actionable.Value != 791 || f.Open.Value != 796 {
		t.Errorf("actionable %d open %d, want 791 796", f.Actionable.Value, f.Open.Value)
	}
	if f.Actionable.Drill != "/findings?priority_class=P0,P1,P2,P3&state=open" {
		t.Errorf("actionable drill %s", f.Actionable.Drill)
	}
	var sum int64
	for i, c := range f.Classes {
		if c.Key != priorityClasses[i] || c.Drill != "/findings?priority_class="+c.Key+"&state=open" {
			t.Errorf("class %d = %+v", i, c)
		}
		sum += c.Value
	}
	if sum != f.Actionable.Value {
		t.Errorf("arcs sum %d, ring total %d", sum, f.Actionable.Value)
	}
	// Severity in severity order, zero rows left out, each a list.
	keys := make([]string, 0, len(f.Severity))
	for _, r := range f.Severity {
		keys = append(keys, r.Key)
		if r.Drill != "/findings?severity="+r.Key+"&state=open" {
			t.Errorf("severity drill %s", r.Drill)
		}
	}
	if strings.Join(keys, ",") != "critical,high,medium,low" {
		t.Errorf("severity order %v", keys)
	}
	if f.PastSLA.Value != 43 || f.InProgress.Value != 112 || f.Fixed.Value != 318 || f.Accepted.Value != 22 || f.FalsePositive.Value != 97 {
		t.Errorf("outcomes %+v %+v %+v %+v %+v", f.PastSLA, f.InProgress, f.Fixed, f.Accepted, f.FalsePositive)
	}
	since := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	if !f.Since.Equal(since) || !facts.since.Equal(since) {
		t.Errorf("since %v (facts %v), want %v", f.Since, facts.since, since)
	}
	if f.Fixed.Drill != "/findings?resolved_at_gte="+url.QueryEscape("2026-09-26T00:00:00Z")+"&status=resolved" {
		t.Errorf("fixed drill %s", f.Fixed.Drill)
	}
	if f.InProgress.Drill != "/findings?status=in_progress" {
		t.Errorf("in progress drill %s", f.InProgress.Drill)
	}
	if f.Stages == nil || len(f.Stages.Stages) != 5 {
		t.Fatalf("stages %+v", f.Stages)
	}

	in := f.Intake
	if in == nil || f.IntakeReason != "" {
		t.Fatalf("intake %v reason %s", in, f.IntakeReason)
	}
	if len(facts.intakeTenants) != 1 || facts.intakeTenants[0] != scope.TenantID {
		t.Errorf("intake read for %v, want %v", facts.intakeTenants, scope.TenantID)
	}
	health := map[string]string{}
	for _, src := range in.Sources {
		health[src.Tool] = src.Health
		want := "/findings/imports?origin=" + src.Origin + "&since=2026-09-26T00:00:00Z&tool=" + src.Tool
		if src.Drill != want {
			t.Errorf("source drill %s, want %s", src.Drill, want)
		}
	}
	if health["nuclei"] != HealthOK || health["cloud"] != HealthStale || health["unknown"] != HealthFailed {
		t.Errorf("health %v", health)
	}
	if in.Failing != 1 || in.Stale != 1 {
		t.Errorf("failing %d stale %d", in.Failing, in.Stale)
	}
	if in.Totals.Received != 602 || in.Totals.Receipts != 42 || in.Totals.NotStored != 18 {
		t.Errorf("totals %+v", in.Totals)
	}
	if !in.Totals.LastAt.Equal(now.Add(-30 * time.Minute)) {
		t.Errorf("last receipt %v", in.Totals.LastAt)
	}
	n := in.Noise
	if n.New+n.Merged+n.NotStored != n.Received {
		t.Errorf("noise parts %+v do not sum to received", n)
	}
	// new = created + reopened = 144 + 4, the receipt list's New plus
	// Reopened; the 8 suppressed are inside it.
	if n.New != 148 || n.New != in.Totals.Created+in.Totals.Reopened || n.Suppressed != 8 || n.NotStored != 18 || n.Merged != 602-144-4-18 {
		t.Errorf("noise %+v", n)
	}
	if in.Drill != "/findings/imports?since=2026-09-26T00:00:00Z" {
		t.Errorf("intake drill %s", in.Drill)
	}
	if in.FalsePositive.Value != 97 || in.FalsePositive.Drill != f.FalsePositive.Drill {
		t.Errorf("false positive %+v", in.FalsePositive)
	}
}

// A personal read never carries organization receipts: no intake read is
// made, the reason says why, and every findings figure is the read's scope.
func TestExposureFlow_PersonalReadHasNoIntake(t *testing.T) {
	facts := flowFacts()
	s := NewService(nil, nil, facts, nil)
	fixedNow(s)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, ctemWidget("exposure.flow", "flow", 0), true, scope)
	if v.State != StateReady || v.Flow == nil {
		t.Fatalf("state %s flow %v", v.State, v.Flow)
	}
	if v.Flow.Intake != nil || v.Flow.IntakeReason != ReasonOrganizationOnly {
		t.Errorf("personal flow intake %v reason %s", v.Flow.Intake, v.Flow.IntakeReason)
	}
	if len(facts.intakeTenants) != 0 {
		t.Errorf("a personal read read the receipts")
	}
	for _, got := range facts.scopes {
		if got.Assets != scope.Assets || got.CampaignViewer != scope.CampaignViewer {
			t.Fatalf("a flow read used another scope: %+v", got)
		}
	}

	// An unrestricted personal scope (an administrator's) is still not the
	// organization read.
	facts.intakeTenants = nil
	admin := dashboard.ReadScope{TenantID: shared.NewID(), Assets: &shared.DataScope{Unrestricted: true}}
	v = s.widget(context.Background(), 0, ctemWidget("ingest.intake", "intake", 0), true, admin)
	if v.State != StateNotMeasured || v.Reason != ReasonOrganizationOnly || v.Intake != nil || len(facts.intakeTenants) != 0 {
		t.Errorf("personal intake = %+v", v)
	}
}

func TestIntake_NoReceiptsIsNotMeasured(t *testing.T) {
	facts := flowFacts()
	facts.intake = nil
	s := NewService(nil, nil, facts, nil)
	fixedNow(s)
	v := s.widget(context.Background(), 0, ctemWidget("ingest.intake", "intake", 0), true, orgScope(shared.NewID()))
	if v.State != StateNotMeasured || v.Reason != ReasonNoReceipts || v.Intake == nil || v.Intake.Totals.Received != 0 {
		t.Errorf("empty intake = %+v", v)
	}
	v = s.widget(context.Background(), 0, ctemWidget("exposure.flow", "flow", 0), true, orgScope(shared.NewID()))
	if v.State != StateReady || v.Flow.IntakeReason != ReasonNoReceipts {
		t.Errorf("flow without receipts = %s %s", v.State, v.Flow.IntakeReason)
	}
}

func TestNoiseOf_ClampsAndSums(t *testing.T) {
	// Still detected larger than the remainder (a report counts a sighting
	// more than once): merged is the remainder, never negative.
	n := noiseOf(IntakeSource{Received: 10, Created: 6, Reopened: 2, Suppressed: 7, NotStored: 5})
	if n.Merged != 0 || n.New != 8 {
		t.Errorf("noise %+v", n)
	}
	n = noiseOf(IntakeSource{Received: 100, Created: 10, Reopened: 5, Suppressed: 3, NotStored: 2})
	if n.New+n.Merged+n.NotStored != 100 || n.New != 15 || n.Suppressed != 3 {
		t.Errorf("noise %+v", n)
	}
}

func TestSourceHealth(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	minute := time.Minute
	for _, tc := range []struct {
		name string
		row  dashboard.IntakeRow
		want string
	}{
		{"no interval yet", dashboard.IntakeRow{LastAt: now.Add(-30 * day), LastStatus: "completed"}, HealthOK},
		{"weekly, five days ago", dashboard.IntakeRow{LastAt: now.Add(-5 * day), LastStatus: "completed", MedianGap: ptrDur(7 * day)}, HealthOK},
		{"weekly, fifteen days ago", dashboard.IntakeRow{LastAt: now.Add(-15 * day), LastStatus: "completed", MedianGap: ptrDur(7 * day)}, HealthStale},
		{"every minute, never before a day", dashboard.IntakeRow{LastAt: now.Add(-23 * time.Hour), LastStatus: "completed", MedianGap: &minute}, HealthOK},
		{"failed wins", dashboard.IntakeRow{LastAt: now, LastStatus: "failed", MedianGap: &minute}, HealthFailed},
	} {
		if got := sourceHealth(tc.row, now); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func ptrDur(d time.Duration) *time.Duration { return &d }

func TestFlowSpec_NoComparison(t *testing.T) {
	for _, metric := range []string{"exposure.flow", "ingest.intake"} {
		cfg := map[string]any{"v": 2, "id": "w_t1", "data": map[string]any{"kind": "metric", "metric": metric,
			"time": map[string]any{"range": "90d", "compare": "previous_period"}}, "viz": map[string]any{}}
		if _, err := dashboard.ParseWidgetSpec("metric", cfg); err == nil {
			t.Errorf("%s accepted a comparison", metric)
		}
		cfg["data"].(map[string]any)["time"] = map[string]any{"range": "90d"}
		spec, err := dashboard.ParseWidgetSpec("metric", cfg)
		if err != nil {
			t.Fatalf("%s 90d: %v", metric, err)
		}
		if spec.Viz.Type != dashboard.VizFlow && spec.Viz.Type != dashboard.VizIntake {
			t.Errorf("%s default viz %s", metric, spec.Viz.Type)
		}
	}
}

// A source says what it contributes, carries its senders, and is as
// unhealthy as its worst sender: a failing sensor shows on every tool it
// feeds. Only the tenant's own sensors link to a sensor page.
func TestIntake_KindsInstancesAndWorstHealth(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	hour := time.Hour
	facts := &ctemFacts{intake: []dashboard.IntakeRow{
		{Origin: "sensor", Tool: "nuclei", Receipts: 3, Received: 12, LastAt: now.Add(-time.Hour), LastStatus: "completed",
			Instances: []dashboard.IntakeInstanceRow{
				{Kind: "sensor", ID: "11111111-1111-1111-1111-111111111111", Name: "edge", Owned: true, Received: 7,
					LastAt: now.Add(-time.Hour), LastStatus: "completed"},
				{Kind: "sensor", ID: "22222222-2222-2222-2222-222222222222", Received: 5,
					LastAt: now.Add(-2 * time.Hour), LastStatus: "failed"},
			}},
		{Origin: "sensor", Tool: "subfinder", Receipts: 2, Received: 0, Assets: 50, LastAt: now.Add(-time.Hour), LastStatus: "completed",
			Instances: []dashboard.IntakeInstanceRow{{Kind: "sensor", ID: "11111111-1111-1111-1111-111111111111", Owned: true,
				Assets: 50, LastAt: now.Add(-72 * time.Hour), LastStatus: "completed", MedianGap: &hour}}},
		{Origin: "platform", Tool: "version-match", Receipts: 1, Received: 4, Created: 4, LastAt: now, LastStatus: "completed",
			Instances: []dashboard.IntakeInstanceRow{{Kind: "platform", ID: "platform", Received: 4, LastAt: now, LastStatus: "completed"}}},
	}}
	s := NewService(nil, nil, facts, nil)
	s.now = func() time.Time { return now }
	in, err := s.intake(context.Background(), orgScope(shared.NewID()), now.Add(-30*24*time.Hour), FlowFigure{})
	if err != nil {
		t.Fatalf("intake: %v", err)
	}
	by := map[string]IntakeSource{}
	for _, src := range in.Sources {
		by[src.Tool] = src
	}
	nuc, sub, vm := by["nuclei"], by["subfinder"], by["version-match"]
	if nuc.Kind != SourceKindDetection || sub.Kind != SourceKindDiscovery || vm.Kind != SourceKindPlatform {
		t.Errorf("kinds %s %s %s", nuc.Kind, sub.Kind, vm.Kind)
	}
	if nuc.Health != HealthFailed {
		t.Errorf("nuclei health %s, want failed (its second sensor failed)", nuc.Health)
	}
	if sub.Health != HealthStale || sub.Assets != 50 {
		t.Errorf("subfinder health %s assets %d, want stale 50", sub.Health, sub.Assets)
	}
	if len(nuc.Instances) != 2 || nuc.Instances[0].SensorHref != "/sensors/11111111-1111-1111-1111-111111111111" ||
		nuc.Instances[1].SensorHref != "" || nuc.Instances[1].Health != HealthFailed {
		t.Errorf("nuclei instances %+v", nuc.Instances)
	}
	if vm.Instances[0].SensorHref != "" {
		t.Errorf("platform instance links a sensor: %+v", vm.Instances[0])
	}
	if in.Totals.Assets != 50 || in.Totals.Received != 16 || in.Noise.New != 4 {
		t.Errorf("totals %+v noise %+v", in.Totals, in.Noise)
	}
	if in.Failing != 1 || in.Stale != 1 {
		t.Errorf("failing %d stale %d", in.Failing, in.Stale)
	}
}
