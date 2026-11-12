package scope

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/contract/webpath"

	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/server/pkg/domain/scanrun"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// SECURITY: the web scope of a path discovery job is strict: GET and HEAD
// only, the per-host request cap, and every exclusion on the target hosts
// denied unless its testing mode is allowed (read_only included).
func TestBuildDiscoveryWebScope_Strict(t *testing.T) {
	tenantID := shared.NewID()
	future := time.Now().Add(time.Hour)
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		pathExclusion(t, tenantID, "*", "/admin", nil, scopedom.TestingReadOnly, nil),
		pathExclusion(t, tenantID, "*.example.com", "/orders", []string{"POST"}, scopedom.TestingBlocked, nil),
		pathExclusion(t, tenantID, "*", "/staging", nil, scopedom.TestingAllowed, &future),
		pathExclusion(t, tenantID, "other.example.net", "/x", nil, scopedom.TestingBlocked, nil),
	}})
	ws, err := svc.BuildDiscoveryWebScope(context.Background(), tenantID, []string{"https://app.example.com"}, 300)
	if err != nil || ws == nil {
		t.Fatalf("scope %+v, %v", ws, err)
	}
	if !slices.Equal(ws.Methods, []string{"GET", "HEAD"}) || ws.MaxRequestsPerHost != 300 {
		t.Fatalf("methods %v cap %d", ws.Methods, ws.MaxRequestsPerHost)
	}
	if !slices.Equal(ws.DenyPaths, []string{"/admin", "/orders"}) {
		t.Fatalf("deny %v, want the read_only and the method-scoped rule, not the allowed or other-host one", ws.DenyPaths)
	}
	raw, _ := json.Marshal(ws)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if m["max_requests_per_host"] != float64(300) {
		t.Fatalf("wire form %s", raw)
	}
	// Every spelling of the excluded path is denied with the sensor's reading.
	for _, p := range []string{"/Admin", "/%61dmin", "/x/../admin", "/admin;x", "/admin/users"} {
		clean, err := webpath.CleanPath(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if _, denied := webpath.Denied(clean, ws.DenyPaths); !denied {
			t.Errorf("%s is not denied by %v", p, ws.DenyPaths)
		}
	}
	// Bounds of the cap; never nil without exclusions.
	svc = newFilterService(&fakeExclusionRepo{})
	ws, err = svc.BuildDiscoveryWebScope(context.Background(), tenantID, []string{"https://app.example.com"}, 10)
	if err != nil || ws == nil || ws.MaxRequestsPerHost != MinDiscoveryRequestsPerHost || len(ws.DenyPaths) != 0 {
		t.Fatalf("no exclusions: %+v, %v", ws, err)
	}
	svc = newFilterService(&fakeExclusionRepo{err: errors.New("db down")})
	if _, err := svc.BuildDiscoveryWebScope(context.Background(), tenantID, []string{"https://app.example.com"}, 300); err == nil {
		t.Fatal("a failed lookup built a discovery scope")
	}
}

// SECURITY: a path discovery job always gets the strict scope, with the cap
// its config names, even when nothing else would attach one; a scope the
// caller wrote is replaced.
func TestWebJobGuard_DiscoveryJobStrict(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		pathExclusion(t, tenantID, "*", "/admin", nil, scopedom.TestingReadOnly, nil),
	}})
	g := NewWebJobGuard(svc, nil)
	g.SetDiscoveryGate(&fakeDispatchGate{per: 300})
	cmd := newCmd(t, commanddom.CommandTypeScan, map[string]any{
		"scanner": "webguess", "capability": "enumerate.web_paths@1", "targets": []string{"https://app.example.com"},
		"scanner_config": map[string]any{"max_requests": 250},
		"web_scope":      map[string]any{"methods": []string{"POST"}},
	})
	cmd.TenantID = tenantID
	if err := g.GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	ws, _ := payloadOf(t, cmd)[commanddom.PayloadKeyWebScope].(map[string]any)
	if ws == nil || ws["max_requests_per_host"] != float64(250) || len(ws["methods"].([]any)) != 2 {
		t.Fatalf("web scope %v", ws)
	}
	if got := denyPaths(payloadOf(t, cmd)); !slices.Equal(got, []string{"/admin"}) {
		t.Fatalf("deny %v", got)
	}
	// No cap in the config: the default.
	cmd = newCmd(t, commanddom.CommandTypeScan, map[string]any{
		"scanner": "webguess", "targets": []string{"https://app.example.com"}})
	cmd.TenantID = tenantID
	if err := g.GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	ws, _ = payloadOf(t, cmd)[commanddom.PayloadKeyWebScope].(map[string]any)
	if ws == nil || ws["max_requests_per_host"] != float64(DefaultDiscoveryRequestsPerHost) {
		t.Fatalf("default cap: %v", ws)
	}
}

// fakeDispatchGate is the dispatch gate of path discovery: it grants the
// requested cap up to per, or refuses with err (check refuses at the checks,
// err at the claim). It records the order of its calls.
type fakeDispatchGate struct {
	per      int
	err      error
	checkErr error
	calls    int
	run      *shared.ID
	order    []string
	claimed  shared.ID
	released []shared.ID
}

func (f *fakeDispatchGate) CheckPathDispatch(context.Context, shared.ID, []string) error {
	f.order = append(f.order, "check")
	return f.checkErr
}

func (f *fakeDispatchGate) ClaimPathDispatch(_ context.Context, _, cmd shared.ID, run *shared.ID, _ []string, requested int) (int, error) {
	f.calls++
	f.run = run
	f.order = append(f.order, "claim")
	if f.err != nil {
		return 0, f.err
	}
	f.claimed = cmd
	if requested <= 0 {
		requested = f.per
	}
	return min(requested, f.per), nil
}

func (f *fakeDispatchGate) ReleasePathDispatch(_ context.Context, _, cmd shared.ID, _ []string) error {
	f.order = append(f.order, "release")
	f.released = append(f.released, cmd)
	return nil
}

// SECURITY: every path discovery job passes the one dispatch gate before it
// is stored. A refusal of the gate refuses the job; without a gate wired the
// job is refused; the cap is the gate's, whatever the job asks for; the run
// of the payload reaches the gate (the per-host budget of a run).
func TestWebJobGuard_DiscoveryUsesTheDispatchGate(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{})
	job := func(cfg map[string]any, run string) *commanddom.Command {
		p := map[string]any{"scanner": "webguess", "targets": []string{"https://app.example.com"}, "scanner_config": cfg}
		if run != "" {
			p["scan_run_id"] = run
		}
		c := newCmd(t, commanddom.CommandTypeScan, p)
		c.TenantID = tenantID
		return c
	}

	// No gate: refused.
	if err := NewWebJobGuard(svc, nil).GuardCreate(context.Background(), job(nil, "")); !errors.Is(err, commanddom.ErrWebScopeUnwired) {
		t.Fatalf("no gate: %v", err)
	}
	// A refusal of the gate refuses the job; nothing is stored.
	refusing := &fakeDispatchGate{checkErr: shared.NewDomainError("PATH_DISCOVERY_REFUSED", "ran recently", shared.ErrValidation)}
	g := NewWebJobGuard(svc, nil)
	g.SetDiscoveryGate(refusing)
	cmd := job(nil, "")
	before := string(cmd.Payload)
	if err := g.GuardCreate(context.Background(), cmd); err == nil || string(cmd.Payload) != before {
		t.Fatalf("a refused job was admitted: %v", err)
	}
	// A request far above the platform's cap is signed at the cap.
	gate := &fakeDispatchGate{per: 300}
	g.SetDiscoveryGate(gate)
	run := shared.NewID()
	cmd = job(map[string]any{"max_requests": 99999999}, run.String())
	if err := g.GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	ws, _ := payloadOf(t, cmd)[commanddom.PayloadKeyWebScope].(map[string]any)
	if ws == nil || ws["max_requests_per_host"] != float64(300) {
		t.Fatalf("cap %v, want the platform's 300", ws)
	}
	if gate.run == nil || *gate.run != run {
		t.Fatalf("the gate was not told the run: %v", gate.run)
	}
}

// SECURITY: a path discovery job requires net.confined@1 like a nuclei scan:
// only the confined forwarder holds the tool to its scope and request cap.
// Without a confined sensor in the organization the job is refused.
func TestWebJobGuard_DiscoveryRequiresConfinement(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{})
	g := NewWebJobGuard(svc, fakeConfined{})
	g.SetDiscoveryGate(&fakeDispatchGate{per: 300})
	cmd := newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "webguess", "targets": []string{"https://app.example.com"}})
	cmd.TenantID = tenantID
	err := g.GuardCreate(context.Background(), cmd)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != scanrundom.FailureNoConfinedSensor {
		t.Fatalf("no confined sensor: %v", err)
	}
	g2 := NewWebJobGuard(svc, nil)
	g2.SetDiscoveryGate(&fakeDispatchGate{per: 300})
	cmd = newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "webguess", "targets": []string{"https://app.example.com"}})
	cmd.TenantID = tenantID
	if err := g2.GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	feats, _ := payloadOf(t, cmd)[commanddom.PayloadKeyRequiredFeatures].([]any)
	if len(feats) != 1 || feats[0] != "net.confined@1" {
		t.Fatalf("required features %v", feats)
	}
}

// SECURITY: the ledger claim is the LAST step of the guard. A job refused for
// the lack of a confined sensor never reaches the claim, so it spends no
// origin's 30 days; a job that is accepted claims once, for its own command.
func TestWebJobGuard_DiscoveryClaimsLast(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{})
	mk := func() *commanddom.Command {
		c := newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "webguess", "targets": []string{"https://app.example.com"}})
		c.TenantID = tenantID
		return c
	}
	gate := &fakeDispatchGate{per: 300}
	g := NewWebJobGuard(svc, fakeConfined{})
	g.SetDiscoveryGate(gate)
	if err := g.GuardCreate(context.Background(), mk()); err == nil {
		t.Fatal("a job without a confined sensor was accepted")
	}
	if gate.calls != 0 || slices.Contains(gate.order, "claim") {
		t.Fatalf("the ledger was claimed for a refused job: %v", gate.order)
	}
	gate = &fakeDispatchGate{per: 300}
	g = NewWebJobGuard(svc, nil)
	g.SetDiscoveryGate(gate)
	cmd := mk()
	if err := g.GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gate.order, []string{"check", "claim"}) || gate.claimed != cmd.ID {
		t.Fatalf("order %v, claimed for %v (command %v)", gate.order, gate.claimed, cmd.ID)
	}
	// The repository could not store the command: the claim is given back.
	g.ReleaseCreate(context.Background(), cmd)
	if len(gate.released) != 1 || gate.released[0] != cmd.ID {
		t.Fatalf("released %v", gate.released)
	}
	// Any other job is left alone.
	other := newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "nuclei", "targets": []string{"https://app.example.com"}})
	g.ReleaseCreate(context.Background(), other)
	if len(gate.released) != 1 {
		t.Fatal("a job that is not path discovery released a claim")
	}
}

// SECURITY: the deny paths of a discovery job are written the way every
// other web job's are (scopedom.JobDenyPaths): a "*" segment is cut so a
// sensor before webpath 1.3.1 still holds it, and an escaped path also
// carries its decoded form. Both builders agree on every exclusion.
func TestBuildDiscoveryWebScope_DenyPathsMatchTheJobForm(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		pathExclusion(t, tenantID, "*", "/tenants/*/admin", nil, scopedom.TestingBlocked, nil),
		pathExclusion(t, tenantID, "*", "/files/My%20Docs", nil, scopedom.TestingBlocked, nil),
	}})
	targets := []string{"https://app.example.com"}
	disc, err := svc.BuildDiscoveryWebScope(context.Background(), tenantID, targets, 300)
	if err != nil {
		t.Fatal(err)
	}
	job, err := svc.BuildWebScope(context.Background(), tenantID, targets)
	if err != nil || job == nil {
		t.Fatalf("%+v %v", job, err)
	}
	if !slices.Equal(disc.DenyPaths, job.DenyPaths) {
		t.Fatalf("discovery denies %v, an ordinary web job %v", disc.DenyPaths, job.DenyPaths)
	}
	if !slices.Contains(disc.DenyPaths, "/tenants/") {
		t.Fatalf("the wildcard rule was not cut: %v", disc.DenyPaths)
	}
	for _, p := range []string{"/tenants/7/admin", "/files/My Docs/a.bak", "/files/My%20Docs/a.bak"} {
		clean, err := webpath.CleanPath(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if _, denied := webpath.Denied(clean, disc.DenyPaths); !denied {
			t.Errorf("%s passes %v", p, disc.DenyPaths)
		}
	}
}

// SECURITY: a path discovery job with no origin to probe is refused: no
// claim is made, and the job is not stored.
func TestWebJobGuard_DiscoveryWithoutTargetsIsRefused(t *testing.T) {
	svc := newFilterService(&fakeExclusionRepo{})
	gate := &fakeDispatchGate{per: 300}
	g := NewWebJobGuard(svc, nil)
	g.SetDiscoveryGate(gate)
	for name, p := range map[string]map[string]any{
		"no targets key": {"scanner": "webguess"},
		"empty targets":  {"scanner": "webguess", "targets": []string{}},
		"step payload":   {"scanner": "othertool", "required_capabilities": []string{"enumerate.web_paths"}, "targets": []string{}},
	} {
		cmd := newCmd(t, commanddom.CommandTypeScan, p)
		cmd.TenantID = shared.NewID()
		before := string(cmd.Payload)
		err := g.GuardCreate(context.Background(), cmd)
		if err == nil || !errors.Is(err, shared.ErrValidation) || string(cmd.Payload) != before {
			t.Errorf("%s: a discovery job with no origin was admitted: %v", name, err)
		}
		if gate.calls != 0 {
			t.Errorf("%s: the gate was called %d times", name, gate.calls)
		}
	}
}
