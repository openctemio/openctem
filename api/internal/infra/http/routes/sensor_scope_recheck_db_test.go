package routes

// The claim-time scope re-check (docs/architecture/active-probe-gate.md,
// "Re-check at claim") over the real protocol v2 and v3 wiring and a
// migrated database: a scan job whose targets were refused after it was
// queued is narrowed (in the response and in the stored payload) or failed
// with SCOPE_CHANGED, the response shapes stay the protocol's, a gate error
// leaves the job pending, and a sensor never gets another tenant's job.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/openctemio/openctem/api/internal/app/command"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// scopeGateStub refuses the targets the test names.
type scopeGateStub struct {
	mu       sync.Mutex
	excluded map[string]bool
	tier     map[string]bool
	err      error
	inputs   []scanapp.DispatchTargetsInput
}

func newScopeGateStub() *scopeGateStub {
	return &scopeGateStub{excluded: map[string]bool{}, tier: map[string]bool{}}
}

func (g *scopeGateStub) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inputs = append(g.inputs, in)
	if g.err != nil {
		return nil, g.err
	}
	out := &scanapp.DispatchTargets{}
	for _, t := range in.Targets {
		switch {
		case g.excluded[t]:
			out.Excluded = append(out.Excluded, t)
		case g.tier[t]:
			out.Refused = append(out.Refused, scanapp.RefusedTarget{Target: t, Code: scopedom.RefusalTierExceeds})
		default:
			out.Allowed = append(out.Allowed, t)
		}
	}
	return out, nil
}

func (g *scopeGateStub) lastInput(t *testing.T) scanapp.DispatchTargetsInput {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.inputs) == 0 {
		t.Fatal("the gate was not called")
	}
	return g.inputs[len(g.inputs)-1]
}

const recheckPayload = `{"scanner":"semgrep","targets":["keep.example.com","drop.example.com"],"timeout_seconds":600}`

func createScan(t *testing.T, cmds *command.Service, tenantID, payload string, gate *commanddom.DispatchGate) string {
	t.Helper()
	c, err := cmds.Create(context.Background(), command.CreateInput{TenantID: tenantID, Type: "scan", Priority: "normal",
		Payload: json.RawMessage(payload), ExpiresIn: 3600, DispatchGate: gate})
	if err != nil {
		t.Fatalf("create command: %v", err)
	}
	return c.ID.String()
}

func readCommand(t *testing.T, h *ctlHarness, id string) (status, errMsg string, targets []string, gate []byte) {
	t.Helper()
	var payload []byte
	var em *string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT status, error_message, payload, dispatch_gate FROM commands WHERE id = $1`, id).
		Scan(&status, &em, &payload, &gate); err != nil {
		t.Fatalf("read command: %v", err)
	}
	if em != nil {
		errMsg = *em
	}
	var p struct {
		Targets []string `json:"targets"`
	}
	_ = json.Unmarshal(payload, &p)
	return status, errMsg, p.Targets, gate
}

func commandTargetsOf(t *testing.T, c protov2.Command) []string {
	t.Helper()
	var p struct {
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(c.Payload, &p); err != nil {
		t.Fatalf("payload %s: %v", c.Payload, err)
	}
	return p.Targets
}

func TestSensorV2ScopeRecheck_ClaimNNarrowsAndFails(t *testing.T) {
	gate := newScopeGateStub()
	h := newCtlHarness(t, command.WithScopeRecheck(gate))
	s := h.newSensor(h.tenantID, "claimer")
	h.setMaxJobs(s.id, 10)
	actor := shared.NewID().String()
	narrow := createScan(t, h.cmds, h.tenantID, recheckPayload, &commanddom.DispatchGate{Tier: 2, ActScope: true, Actor: actor})
	gone := createScan(t, h.cmds, h.tenantID, `{"scanner":"semgrep","target":"tier.example.com"}`, &commanddom.DispatchGate{Tier: 1})
	same := createScan(t, h.cmds, h.tenantID, `{"scanner":"semgrep","target":"same.example.com"}`, &commanddom.DispatchGate{Tier: 1})
	gate.excluded["drop.example.com"] = true
	gate.tier["tier.example.com"] = true

	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	list := decodeAs[protov2.CommandList](t, raw)
	got := map[string]protov2.Command{}
	for _, c := range list.Commands {
		got[c.ID] = c
	}
	if len(got) != 2 {
		t.Fatalf("claimed %s, want the narrowed and the unchanged job", raw)
	}
	if c, ok := got[narrow]; !ok || c.Status != "acknowledged" || strings.Join(commandTargetsOf(t, c), ",") != "keep.example.com" {
		t.Fatalf("narrowed job: %+v", got[narrow])
	}
	if c, ok := got[same]; !ok || !strings.Contains(string(c.Payload), "same.example.com") {
		t.Fatalf("unchanged job: %+v", got[same])
	}
	// The recorded gate inputs reached the gate.
	sawActor := false
	for _, in := range gate.inputs {
		if in.FallbackUser != nil && in.FallbackUser.String() == actor && in.ActScope && *in.Tier == scopedom.TierIntrusive && in.Recheck {
			sawActor = true
		}
	}
	if !sawActor {
		t.Fatalf("the recorded dispatch inputs did not reach the gate: %+v", gate.inputs)
	}

	st, _, targets, rec := readCommand(t, h, narrow)
	var stored commanddom.DispatchGate
	_ = json.Unmarshal(rec, &stored)
	if st != "acknowledged" || strings.Join(targets, ",") != "keep.example.com" ||
		stored != (commanddom.DispatchGate{Tier: 2, ActScope: true, Actor: actor}) {
		t.Fatalf("stored narrowed job: %s %v %s", st, targets, rec)
	}
	st, msg, _, _ := readCommand(t, h, gone)
	if st != "failed" || !strings.HasPrefix(msg, "SCOPE_CHANGED: ") || !strings.Contains(msg, "tier.example.com (tier_exceeds)") {
		t.Fatalf("stored refused job: %s %q", st, msg)
	}

	// A second claim attempt does not hand it out or record again.
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+gone+"/claim", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("claim of the failed job: %d %s", resp.StatusCode, raw)
	}
	if st2, msg2, _, _ := readCommand(t, h, gone); st2 != "failed" || msg2 != msg {
		t.Fatalf("second claim changed the failed job: %s %q", st2, msg2)
	}
}

func TestSensorV2ScopeRecheck_ListingPollAndClaimByID(t *testing.T) {
	gate := newScopeGateStub()
	h := newCtlHarness(t, command.WithScopeRecheck(gate))
	s := h.newSensor(h.tenantID, "lister")
	id := createScan(t, h.cmds, h.tenantID, recheckPayload, &commanddom.DispatchGate{Tier: 1})
	gate.excluded["drop.example.com"] = true

	// The listing poll (no capacity feature) shows the narrowed job.
	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil)
	h.want(resp, raw, 200, "")
	list := decodeAs[protov2.CommandList](t, raw)
	if len(list.Commands) != 1 || strings.Join(commandTargetsOf(t, list.Commands[0]), ",") != "keep.example.com" {
		t.Fatalf("listing poll: %s", raw)
	}

	// Then keep.example.com is excluded too: the claim by id refuses the
	// job as claimed (the sensor drops it) and fails it with SCOPE_CHANGED.
	gate.excluded["keep.example.com"] = true
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", nil)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(raw), string(protov2.ProblemCommandClaimed)) {
		t.Fatalf("claim by id: %d %s", resp.StatusCode, raw)
	}
	if st, msg, _, _ := readCommand(t, h, id); st != "failed" || !strings.Contains(msg, "keep.example.com (excluded)") {
		t.Fatalf("stored: %s %q", st, msg)
	}
}

func TestSensorV2ScopeRecheck_GateErrorLeavesTheJobPending(t *testing.T) {
	gate := newScopeGateStub()
	gate.err = errors.New("scope store unavailable")
	h := newCtlHarness(t, command.WithScopeRecheck(gate))
	s := h.newSensor(h.tenantID, "claimer")
	h.setMaxJobs(s.id, 10)
	id := createScan(t, h.cmds, h.tenantID, recheckPayload, &commanddom.DispatchGate{Tier: 1})

	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	if l := decodeAs[protov2.CommandList](t, raw); len(l.Commands) != 0 {
		t.Fatalf("claimed %s while the gate could not decide", raw)
	}
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("claim by id: %d %s", resp.StatusCode, raw)
	}
	if st, _, targets, _ := readCommand(t, h, id); st != "pending" || len(targets) != 2 {
		t.Fatalf("stored: %s %v, want pending and unchanged", st, targets)
	}

	gate.mu.Lock()
	gate.err = nil
	gate.mu.Unlock()
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	if l := decodeAs[protov2.CommandList](t, raw); len(l.Commands) != 1 || l.Commands[0].ID != id {
		t.Fatalf("after the gate recovered: %s", raw)
	}
}

// Another tenant's job is never re-checked for, nor handed to, a sensor:
// the claim stays tenant-scoped.
func TestSensorV2ScopeRecheck_TenantIsolation(t *testing.T) {
	gate := newScopeGateStub()
	h := newCtlHarness(t, command.WithScopeRecheck(gate))
	other := h.newTenant()
	a := h.newSensor(h.tenantID, "a")
	h.setMaxJobs(a.id, 10)
	foreign := createScan(t, h.cmds, other, `{"scanner":"semgrep","target":"drop.example.com"}`, &commanddom.DispatchGate{Tier: 1})
	gate.excluded["drop.example.com"] = true

	resp, raw := h.call(a.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	if l := decodeAs[protov2.CommandList](t, raw); len(l.Commands) != 0 {
		t.Fatalf("sensor a got %s", raw)
	}
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+foreign+"/claim", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("claim of another tenant's job: %d %s", resp.StatusCode, raw)
	}
	if st, _, _, _ := readCommand(t, h, foreign); st != "pending" {
		t.Fatalf("another tenant's job = %s", st)
	}
	for _, in := range gate.inputs {
		if in.TenantID.String() == other {
			t.Fatal("the gate ran for another tenant's job")
		}
	}
}

func TestSensorV3ScopeRecheck_ClaimCommands(t *testing.T) {
	gate := newScopeGateStub()
	h := newV3HarnessWith(t, []command.Option{command.WithScopeRecheck(gate)})
	tid := h.newTenant()
	s := h.newKeyBound(tid)
	ctx := context.Background()
	gate.excluded["drop.example.com"] = true

	for _, grpc := range []bool{false, true} {
		narrow := createScan(t, h.cmds, tid, recheckPayload, &commanddom.DispatchGate{Tier: 1})
		gone := createScan(t, h.cmds, tid, `{"scanner":"semgrep","target":"drop.example.com"}`, &commanddom.DispatchGate{Tier: 1})
		claimed, err := h.client(s, grpc).ClaimCommands(ctx, connect.NewRequest(&sensorv3.ClaimCommandsRequest{Limit: 5}))
		if err != nil {
			t.Fatalf("claim (grpc=%v): %v", grpc, err)
		}
		list := decodeAs[protov2.CommandList](t, claimed.Msg.GetCommandsJson())
		if len(list.Commands) != 1 || list.Commands[0].ID != narrow ||
			strings.Join(commandTargetsOf(t, list.Commands[0]), ",") != "keep.example.com" {
			t.Fatalf("claimed (grpc=%v) %s", grpc, claimed.Msg.GetCommandsJson())
		}
		var st, msg string
		if err := h.db.QueryRow(`SELECT status, error_message FROM commands WHERE id = $1`, gone).Scan(&st, &msg); err != nil {
			t.Fatal(err)
		}
		if st != "failed" || !strings.HasPrefix(msg, "SCOPE_CHANGED: ") {
			t.Fatalf("refused job (grpc=%v): %s %q", grpc, st, msg)
		}
		// Settle the claimed job so the next round starts empty.
		h.exec(`UPDATE commands SET status = 'completed' WHERE id = $1`, narrow)
	}
	if in := gate.lastInput(t); in.SensorID == nil || in.SensorID.String() != s.id || in.TenantID.String() != tid {
		t.Fatalf("gate input %+v", in)
	}
}
