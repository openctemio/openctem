package command

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/server/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/scanident"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakePlatformIdentity struct {
	layer scanident.PlatformLayer
	err   error
}

func (f fakePlatformIdentity) PlatformLayer(context.Context) (scanident.PlatformLayer, error) {
	return f.layer, f.err
}

// identitySensors answers one sensor per tenant (a lookup is tenant-scoped:
// another tenant's id is not found).
type identitySensors map[shared.ID]*sensordom.Sensor

func (s identitySensors) GetByTenantAndID(_ context.Context, tenantID, _ shared.ID) (*sensordom.Sensor, error) {
	if sen, ok := s[tenantID]; ok {
		return sen, nil
	}
	return nil, shared.ErrNotFound
}

func sensorWith(caps ...string) *sensordom.Sensor {
	sen := &sensordom.Sensor{}
	sen.Reported.Capabilities = caps
	return sen
}

type noProgramRules struct{ r *bp.JobRules }

func (n noProgramRules) JobRules(context.Context, shared.ID, []string, time.Time) (*bp.JobRules, error) {
	return n.r, nil
}

func identityCmd(tenant shared.ID, payload string) *commanddom.Command {
	return &commanddom.Command{ID: shared.NewID(), TenantID: tenant, Type: commanddom.CommandTypeScan,
		Status: commanddom.CommandStatusPending, Payload: json.RawMessage(payload)}
}

func identityService(org perTenantHTTPPolicy, plat scanident.PlatformLayer, sensors identitySensors) (*Service, *passiveFailRepo, *passiveCodes) {
	repo := &passiveFailRepo{}
	codes := &passiveCodes{got: map[shared.ID]string{}}
	return &Service{repo: repo, logger: logger.NewNop(), now: time.Now, httpPolicy: org,
		platformIdentity: fakePlatformIdentity{layer: plat}, sensors: sensors, failures: codes}, repo, codes
}

func deliveredPolicy(t *testing.T, c *commanddom.Command) map[string]any {
	t.Helper()
	var f map[string]json.RawMessage
	if err := json.Unmarshal(c.Payload, &f); err != nil {
		t.Fatal(err)
	}
	pol := map[string]any{}
	if raw, ok := f["http_policy"]; ok {
		if err := json.Unmarshal(raw, &pol); err != nil {
			t.Fatal(err)
		}
	}
	return pol
}

// SECURITY (fail closed): a job that requires identification but carries no
// header and no query parameter is failed at claim with
// IDENTIFICATION_REQUIRED_MISSING and a message naming the fix; it is never
// delivered.
func TestRequiredIdentificationWithoutMarkerFailsAtClaim(t *testing.T) {
	tid, sid := shared.NewID(), shared.NewID()
	s, repo, codes := identityService(perTenantHTTPPolicy{tid: {IdentificationRequired: true, UserAgents: []string{"a", "b"}}},
		scanident.PlatformLayer{}, identitySensors{tid: sensorWith(sensordom.CapabilityHTTPIdentity, sensordom.CapabilityHTTPIdentityRequired)})
	cmd := identityCmd(tid, `{"scanner":"nuclei","targets":["app.example.com"]}`)

	if _, err := s.programHoldOne(context.Background(), sid, cmd); !errors.Is(err, ErrIdentificationRequiredMissing) {
		t.Fatalf("claim by id: %v, want ErrIdentificationRequiredMissing", err)
	}
	if !slices.Contains(repo.failed, cmd.ID) || codes.got[cmd.ID] != FailureIdentificationRequiredMissing {
		t.Fatalf("not failed with the code: failed=%v codes=%v", repo.failed, codes.got)
	}

	// The batch path drops it too.
	cmd2 := identityCmd(tid, `{"scanner":"nuclei","targets":["app.example.com"]}`)
	out, _ := s.programHold(context.Background(), tid, &sid, []*commanddom.Command{cmd2})
	if len(out) != 0 || codes.got[cmd2.ID] != FailureIdentificationRequiredMissing {
		t.Fatalf("batch kept the job: %d, codes %v", len(out), codes.got)
	}
	if !strings.Contains(ErrIdentificationRequiredMissing.Error(), "header or query parameter") {
		t.Fatalf("the message does not name the fix: %v", ErrIdentificationRequiredMissing)
	}
}

// SECURITY: a sensor that does not report http.identity.required@1 would
// drop the requirement silently: the job waits for one that does (withheld,
// never failed), decided by the report, not the version. A sensor that
// reports it gets the job with every field.
func TestRequiredIdentificationNeedsTheSensorCapability(t *testing.T) {
	tid, sid := shared.NewID(), shared.NewID()
	org := perTenantHTTPPolicy{tid: {IdentificationRequired: true, Headers: map[string]string{"X-Scan": "corp"},
		UserAgents: []string{"ua/1", "ua/2", "ua/3"}, Query: &scanident.Query{Name: "scan", Value: "corp-1"}}}
	old := identitySensors{tid: sensorWith(sensordom.CapabilityHTTPIdentity)}
	s, repo, _ := identityService(org, scanident.PlatformLayer{}, old)
	cmd := identityCmd(tid, `{"scanner":"nuclei","targets":["app.example.com"],"scan_run_id":"run-42"}`)

	if _, err := s.programHoldOne(context.Background(), sid, cmd); !errors.Is(err, ErrSensorCannotRequireIdentification) {
		t.Fatalf("older sensor: %v, want ErrSensorCannotRequireIdentification", err)
	}
	if out, _ := s.programHold(context.Background(), tid, &sid, []*commanddom.Command{cmd}); len(out) != 0 {
		t.Fatal("older sensor got the job in a batch")
	}
	if len(repo.failed) != 0 {
		t.Fatal("a withheld job was failed")
	}
	// No sensor id (an unknown poller): withheld too.
	if out, _ := s.programHold(context.Background(), tid, nil, []*commanddom.Command{cmd}); len(out) != 0 {
		t.Fatal("unknown sensor got the job")
	}

	s.sensors = identitySensors{tid: sensorWith(sensordom.CapabilityHTTPIdentity, sensordom.CapabilityHTTPIdentityRequired)}
	if _, err := s.programHoldOne(context.Background(), sid, cmd); err != nil {
		t.Fatalf("capable sensor: %v", err)
	}
	out, err := s.deliver(context.Background(), sid.String(), []*commanddom.Command{cmd}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pol := deliveredPolicy(t, out[0])
	if pol["identification_required"] != true || pol["user_agent"] != "ua/1" || pol["user_agent_key"] != "run-42" {
		t.Fatalf("delivered %v", pol)
	}
	if uas, _ := pol["user_agents"].([]any); len(uas) != 3 {
		t.Fatalf("user_agents %v", pol["user_agents"])
	}
	if q, _ := pol["query"].(map[string]any); q["name"] != "scan" || q["value"] != "corp-1" {
		t.Fatalf("query %v", pol["query"])
	}
	if hs, _ := pol["headers"].(map[string]any); hs["X-Scan"] != "corp" {
		t.Fatalf("headers %v", pol["headers"])
	}
}

// The rotation key is the job's scan run (sticky per run and host), else
// the command id; a single User-Agent carries no list and no key; rotation
// alone needs no capability gate.
func TestRotationKeyAndListOnTheWire(t *testing.T) {
	tid := shared.NewID()
	s, _, _ := identityService(perTenantHTTPPolicy{tid: {UserAgents: []string{"ua/1", "ua/2"}}}, scanident.PlatformLayer{}, nil)
	cmd := identityCmd(tid, `{"scanner":"nuclei"}`)
	out, err := s.deliver(context.Background(), "s", []*commanddom.Command{cmd}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pol := deliveredPolicy(t, out[0]); pol["user_agent_key"] != cmd.ID.String() || pol["user_agent"] != "ua/1" {
		t.Fatalf("command-id key: %v", pol)
	}
	// A run id that is not a valid key (control characters) falls back.
	bad := identityCmd(tid, `{"scanner":"nuclei","scan_run_id":"a\u0007b"}`)
	out, _ = s.deliver(context.Background(), "s", []*commanddom.Command{bad}, nil, nil)
	if pol := deliveredPolicy(t, out[0]); pol["user_agent_key"] != bad.ID.String() {
		t.Fatalf("invalid run id used as key: %v", pol)
	}
	// Rotation without a requirement: no gate.
	if _, err := s.programHoldOne(context.Background(), shared.NewID(), cmd); err != nil {
		t.Fatalf("rotation alone withheld: %v", err)
	}

	s.httpPolicy = perTenantHTTPPolicy{tid: {UserAgent: "corp"}}
	out, _ = s.deliver(context.Background(), "s", []*commanddom.Command{cmd}, nil, nil)
	pol := deliveredPolicy(t, out[0])
	if _, has := pol["user_agents"]; has || pol["user_agent_key"] != nil || pol["user_agent"] != "corp" {
		t.Fatalf("single value carried a list or key: %v", pol)
	}
}

// A program that requires identification gates the job like any layer; its
// rotation list replaces the organization's whole and is locked; a program's
// single User-Agent removes the organization's list from the wire.
func TestProgramRequiredAndList(t *testing.T) {
	tid, sid := shared.NewID(), shared.NewID()
	s, _, codes := identityService(perTenantHTTPPolicy{tid: {UserAgents: []string{"o/1", "o/2"}}}, scanident.PlatformLayer{},
		identitySensors{tid: sensorWith(sensordom.CapabilityHTTPIdentity, sensordom.CapabilityHTTPIdentityRequired)})
	s.programRules = noProgramRules{r: &bp.JobRules{IdentificationRequired: true, Programs: []string{"p"}}}
	cmd := identityCmd(tid, `{"scanner":"nuclei","targets":["app.example.com"],"scan_run_id":"run-7"}`)
	if _, err := s.programHoldOne(context.Background(), sid, cmd); !errors.Is(err, ErrIdentificationRequiredMissing) {
		t.Fatalf("program required without marker: %v", err)
	}
	if codes.got[cmd.ID] != FailureIdentificationRequiredMissing {
		t.Fatalf("codes %v", codes.got)
	}

	rules := &bp.JobRules{IdentificationRequired: true, Headers: map[string]string{"X-Bug-Bounty": "h1"},
		UserAgents: []string{"b/1", "b/2", "b/3"}, Programs: []string{"p"}}
	s.programRules = noProgramRules{r: rules}
	cmd = identityCmd(tid, `{"scanner":"nuclei","targets":["app.example.com"],"scan_run_id":"run-7"}`)
	got, err := s.programHoldOne(context.Background(), sid, cmd)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.deliver(context.Background(), sid.String(), []*commanddom.Command{cmd}, map[shared.ID]*bp.JobRules{cmd.ID: got}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pol := deliveredPolicy(t, out[0])
	uas, _ := pol["user_agents"].([]any)
	if len(uas) != 3 || uas[0] != "b/1" || pol["user_agent"] != "b/1" || pol["user_agent_locked"] != true ||
		pol["identification_required"] != true || pol["user_agent_key"] != "run-7" {
		t.Fatalf("program overlay %v", pol)
	}

	// A program's single value over the organization's list: no list left.
	cmd = identityCmd(tid, `{"scanner":"nuclei","targets":["app.example.com"]}`)
	out, _ = s.deliver(context.Background(), sid.String(), []*commanddom.Command{cmd},
		map[shared.ID]*bp.JobRules{cmd.ID: {UserAgent: "prog", Programs: []string{"p"}}}, nil)
	pol = deliveredPolicy(t, out[0])
	if _, has := pol["user_agents"]; has || pol["user_agent"] != "prog" {
		t.Fatalf("the organization's list survived a program's single value: %v", pol)
	}
}

// A layer that cannot be read withholds the job (never fails it, never
// sends it without the requirement); jobs that send no HTTP are not gated.
func TestRequiredIdentificationUnreadableAndNonHTTP(t *testing.T) {
	tid, sid := shared.NewID(), shared.NewID()
	s, repo, _ := identityService(perTenantHTTPPolicy{tid: {IdentificationRequired: true}}, scanident.PlatformLayer{}, nil)
	s.platformIdentity = fakePlatformIdentity{err: errors.New("db down")}
	cmd := identityCmd(tid, `{"scanner":"nuclei"}`)
	if _, err := s.programHoldOne(context.Background(), sid, cmd); !errors.Is(err, ErrScopeRecheckUnavailable) {
		t.Fatalf("unreadable layer: %v", err)
	}
	if len(repo.failed) != 0 {
		t.Fatal("failed on an unreadable layer")
	}
	s.platformIdentity = fakePlatformIdentity{}
	other := &commanddom.Command{ID: shared.NewID(), TenantID: tid, Type: commanddom.CommandType("collect"), Payload: json.RawMessage(`{}`)}
	if _, err := s.programHoldOne(context.Background(), sid, other); err != nil {
		t.Fatalf("a non-HTTP job was gated: %v", err)
	}
}

// SECURITY (tenant isolation): on one shared sensor, tenant B's rotation
// list, query parameter and requirement never reach tenant A's job, and B's
// requirement never holds A's job back.
func TestIdentityRotationAndRequiredArePerJobTenant(t *testing.T) {
	a, b, sid := shared.NewID(), shared.NewID(), shared.NewID()
	org := perTenantHTTPPolicy{
		a: {Headers: map[string]string{"X-Org-A": "a"}},
		b: {IdentificationRequired: true, UserAgents: []string{"b-ua/1", "b-ua/2"}, Query: &scanident.Query{Name: "bscan", Value: "b-secret"}},
	}
	// The sensor reports no required capability: B's job waits, A's goes.
	s, _, _ := identityService(org, scanident.PlatformLayer{}, identitySensors{a: sensorWith(), b: sensorWith()})
	ja := identityCmd(a, `{"scanner":"nuclei","targets":["a.example.com"]}`)
	jb := identityCmd(b, `{"scanner":"nuclei","targets":["b.example.com"]}`)
	if out, _ := s.programHold(context.Background(), a, &sid, []*commanddom.Command{ja}); len(out) != 1 {
		t.Fatal("tenant B's requirement held tenant A's job")
	}
	if out, _ := s.programHold(context.Background(), b, &sid, []*commanddom.Command{jb}); len(out) != 0 {
		t.Fatal("tenant B's required job went to a sensor without the capability")
	}
	out, err := s.deliver(context.Background(), sid.String(), []*commanddom.Command{ja, jb}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out[0].Payload)
	for _, leak := range []string{"b-ua", "bscan", "b-secret", "identification_required", "user_agents"} {
		if strings.Contains(got, leak) {
			t.Fatalf("tenant A's job carries %q: %s", leak, got)
		}
	}
	if pb := deliveredPolicy(t, out[1]); pb["identification_required"] != true || strings.Contains(string(out[1].Payload), "X-Org-A") {
		t.Fatalf("tenant B's job: %s", out[1].Payload)
	}
}
