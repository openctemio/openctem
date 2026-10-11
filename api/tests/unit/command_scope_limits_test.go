package unit

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Scope limits in signed jobs (RFC-065 §16.8): a crawler on a target only
// limited entries cover goes only to a sensor that enforces the limits,
// and its signed statement carries them.

// limitGate refuses a limited target (constrained) unless the job goes to
// a sensor that enforces scope limits.
type limitGate struct {
	mu    sync.Mutex
	limit map[string]bool
	jobs  []scopedom.JobShape
}

func (g *limitGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if in.Job != nil {
		g.jobs = append(g.jobs, *in.Job)
	}
	out := &scanapp.DispatchTargets{ZoneOf: map[string]*scanzone.Zone{}}
	for _, t := range in.Targets {
		if g.limit[t] && (in.Job == nil || !in.Job.LimitsEnforced) {
			out.Refused = append(out.Refused, scanapp.RefusedTarget{Target: t, Code: scopedom.RefusalConstrained, Reason: "limited"})
			continue
		}
		out.Allowed = append(out.Allowed, t)
	}
	return out, nil
}

type recordingSigner struct {
	mu  sync.Mutex
	sts []jobsign.Statement
}

func (s *recordingSigner) SignJob(_ context.Context, st jobsign.Statement) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sts = append(s.sts, st)
	return json.RawMessage(`{"payloadType":"x"}`), nil
}

type fixedLimits struct {
	mu    sync.Mutex
	calls []shared.ID
}

func (l *fixedLimits) StatementLimits(_ context.Context, tenantID shared.ID, targets []string, _ scopedom.Tier) ([]jobsign.Limit, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, tenantID)
	var out []jobsign.Limit
	for _, t := range targets {
		if t == "https://shop.example.com/api/" {
			out = append(out, jobsign.Limit{Host: "shop.example.com", Ports: "443", Protocol: "tcp", PathPrefix: "/api"})
		}
	}
	return out, nil
}

type limitsFixture struct {
	tenant, sensorID shared.ID
	repo             *recheckRepo
	gate             *limitGate
	signer           *recordingSigner
	limits           *fixedLimits
	svc              *command.Service
}

func newLimitsFixture(caps []string, signs bool) *limitsFixture {
	f := &limitsFixture{tenant: shared.NewID(), sensorID: shared.NewID(), repo: newRecheckRepo(),
		gate: &limitGate{limit: map[string]bool{"https://shop.example.com/api/": true}}, signer: &recordingSigner{}, limits: &fixedLimits{}}
	tenant := f.tenant
	sn := &sensor.Sensor{ID: f.sensorID, TenantID: &tenant, Reported: sensor.CapabilityReport{Capabilities: caps}}
	opts := []command.Option{command.WithScopeRecheck(f.gate),
		command.WithSensorLookup(policySensorLookup{sensors: map[shared.ID]*sensor.Sensor{f.sensorID: sn}})}
	if signs {
		opts = append(opts, command.WithJobSigner(f.signer))
	}
	f.svc = command.NewService(f.repo, newCmdTestLogger(), opts...)
	f.svc.SetScopeLimits(f.limits)
	return f
}

const crawlPayload = `{"scanner":"katana","targets":["https://shop.example.com/api/","app.example.com"]}`

func (f *limitsFixture) claim(t *testing.T, c *commanddom.Command) *commanddom.Command {
	t.Helper()
	cmds, err := f.svc.Claim(context.Background(), command.ClaimInput{TenantID: f.tenant.String(), SensorID: f.sensorID.String(), Limit: 10, MaxJobs: 10})
	if err != nil {
		t.Fatal(err)
	}
	return find(cmds, c)
}

// SECURITY: a sensor that reports scope.limits@1 gets the crawler on the
// limited target, and the signed statement carries the target's limits.
func TestScopeLimits_EnforcingSensorGetsTheJobWithLimits(t *testing.T) {
	f := newLimitsFixture([]string{"scope.limits@1"}, true)
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, crawlPayload, &commanddom.DispatchGate{Tier: 1, Validated: true})
	got := f.claim(t, c)
	if got == nil {
		t.Fatal("the job was not handed out")
	}
	if len(f.gate.jobs) == 0 || !f.gate.jobs[0].LimitsEnforced {
		t.Fatalf("gate jobs %+v", f.gate.jobs)
	}
	if len(f.signer.sts) != 1 {
		t.Fatalf("statements %d", len(f.signer.sts))
	}
	want := []jobsign.Limit{{Host: "shop.example.com", Ports: "443", Protocol: "tcp", PathPrefix: "/api"}}
	if st := f.signer.sts[0]; !slices.Equal(st.Limits, want) || len(st.Targets) != 2 {
		t.Fatalf("statement limits %+v targets %v", st.Limits, st.Targets)
	}
	if len(f.limits.calls) != 1 || f.limits.calls[0] != f.tenant {
		t.Fatalf("limit lookups %v", f.limits.calls)
	}
}

// SECURITY: a sensor that does not report the capability never gets the
// job, and the job is withheld (not narrowed, not failed) so an enforcing
// sensor can take it; its statements never carry limits.
func TestScopeLimits_NonEnforcingSensorIsWithheld(t *testing.T) {
	f := newLimitsFixture([]string{"scan"}, true)
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, crawlPayload, &commanddom.DispatchGate{Tier: 1, Validated: true})
	if got := f.claim(t, c); got != nil {
		t.Fatal("handed out to a sensor that does not enforce limits")
	}
	stored, err := f.repo.GetByTenantAndID(context.Background(), f.tenant, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != commanddom.CommandStatusPending || string(stored.Payload) != crawlPayload {
		t.Fatalf("stored %s %s", stored.Status, stored.Payload)
	}
	if len(f.gate.jobs) == 0 || f.gate.jobs[0].LimitsEnforced {
		t.Fatalf("gate jobs %+v", f.gate.jobs)
	}
	if len(f.signer.sts) != 0 || len(f.limits.calls) != 0 {
		t.Fatalf("signed %d, limit lookups %d", len(f.signer.sts), len(f.limits.calls))
	}
}

// SECURITY: without a job signer no job carries limits (the sensor would
// have nothing signed to enforce), so the capability does not count; a
// sensor of another tenant reporting it does not count either.
func TestScopeLimits_NeedSigningAndTheTenantsOwnSensor(t *testing.T) {
	f := newLimitsFixture([]string{"scope.limits@1"}, false)
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, crawlPayload, &commanddom.DispatchGate{Tier: 1, Validated: true})
	got := f.claim(t, c)
	if len(f.gate.jobs) == 0 || f.gate.jobs[0].LimitsEnforced {
		t.Fatalf("gate jobs %+v", f.gate.jobs)
	}
	if got != nil && slices.Contains(payloadTargetsOf(t, got.Payload), "https://shop.example.com/api/") {
		t.Fatal("the limited target went out unsigned")
	}

	other := newLimitsFixture([]string{"scope.limits@1"}, true)
	foreign := shared.NewID()
	other.repo = newRecheckRepo()
	sn := &sensor.Sensor{ID: other.sensorID, TenantID: &foreign, Reported: sensor.CapabilityReport{Capabilities: []string{"scope.limits@1"}}}
	other.svc = command.NewService(other.repo, newCmdTestLogger(), command.WithScopeRecheck(other.gate), command.WithJobSigner(other.signer),
		command.WithSensorLookup(policySensorLookup{sensors: map[shared.ID]*sensor.Sensor{other.sensorID: sn}}))
	other.svc.SetScopeLimits(other.limits)
	oc := other.repo.add(other.tenant, commanddom.CommandTypeScan, crawlPayload, &commanddom.DispatchGate{Tier: 1, Validated: true})
	if got := other.claim(t, oc); got != nil {
		t.Fatal("another tenant's sensor counted as enforcing")
	}
	if len(other.signer.sts) != 0 {
		t.Fatalf("signed %d", len(other.signer.sts))
	}
}

func payloadTargetsOf(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var p struct {
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p.Targets
}
