package unit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/command"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Bug-bounty program rules at delivery (RFC-065 §12), on every hand-out
// path of the command service (Poll, claim-N, claim by id).

// programRuleSource answers fixed rules for the targets it knows.
type programRuleSource struct {
	rules   *bp.JobRules
	err     error
	tenants []shared.ID
	calls   int
}

func (p *programRuleSource) JobRules(_ context.Context, tenantID shared.ID, targets []string, _ time.Time) (*bp.JobRules, error) {
	p.calls++
	p.tenants = append(p.tenants, tenantID)
	for _, t := range targets {
		if strings.HasSuffix(t, ".bounty.test") {
			return p.rules, p.err
		}
	}
	return nil, nil
}

const programPayload = `{"scanner":"nuclei","step_key":"probe","targets":["app.bounty.test"],` +
	`"config":{"rate_limit":50,"templates":["x"]},"http_policy":{"headers":{"X-Org":"1"},"user_agent":"org-ua"}}`

func newProgramFixture(src *programRuleSource, sdkVersion string) *recheckFixture {
	f := newRecheckFixture()
	tenant := f.tenant
	lookup := policySensorLookup{sensors: map[shared.ID]*sensor.Sensor{
		f.sensor: {ID: f.sensor, TenantID: &tenant, Build: sensor.BuildInfo{SDKVersion: sdkVersion}},
	}}
	f.svc = command.NewService(f.repo, newCmdTestLogger(), command.WithSensorLookup(lookup), command.WithProgramRules(src))
	f.svc.SetFailureObserver(f.steps)
	return f
}

func payloadMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("payload %s: %v", raw, err)
	}
	return m
}

// The delivered copy carries the program's headers, User-Agent and rate
// cap; the organization's headers stay; the stored command is unchanged.
func TestProgramRules_DeliveredWithTheJob(t *testing.T) {
	for _, path := range handOutPaths {
		t.Run(path.name, func(t *testing.T) {
			src := &programRuleSource{rules: &bp.JobRules{Headers: map[string]string{"X-Bug-Bounty": "jdoe"},
				UserAgent: "jdoe-research", RateLimit: 5, Programs: []string{"Acme"}}}
			f := newProgramFixture(src, "v0.19.0")
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, programPayload, nil)
			got, err := path.run(f, c)
			if err != nil || got == nil {
				t.Fatalf("hand-out: %v %v", got, err)
			}
			p := payloadMap(t, got.Payload)
			pol := p["http_policy"].(map[string]any)
			headers := pol["headers"].(map[string]any)
			if headers["X-Bug-Bounty"] != "jdoe" || headers["X-Org"] != "1" || pol["user_agent"] != "jdoe-research" {
				t.Fatalf("http_policy %v", pol)
			}
			cfg := p["config"].(map[string]any)
			if cfg["rate_limit"] != float64(5) || cfg["templates"] == nil {
				t.Fatalf("config %v", cfg)
			}
			if string(f.repo.commands[c.ID.String()].Payload) != programPayload {
				t.Fatalf("the stored command changed: %s", f.repo.commands[c.ID.String()].Payload)
			}
			if len(src.tenants) == 0 || src.tenants[0] != f.tenant {
				t.Fatalf("rules asked for tenants %v", src.tenants)
			}
		})
	}
}

// A lower rate on the job is kept; a job without config gets one; a job
// on targets no program covers is untouched.
func TestProgramRules_RateCapAndUncoveredJobs(t *testing.T) {
	src := &programRuleSource{rules: &bp.JobRules{RateLimit: 20}}
	f := newProgramFixture(src, "v0.18.0") // no header rule: any SDK
	low := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"targets":["a.bounty.test"],"config":{"rate_limit":2}}`, nil)
	none := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"targets":["a.bounty.test"],"scanner_config":{"rate_limit":0}}`, nil)
	other := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"targets":["owned.example.com"],"config":{"rate_limit":500}}`, nil)
	cmds, err := f.svc.Poll(context.Background(), command.PollInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10})
	if err != nil || len(cmds) != 3 {
		t.Fatalf("poll: %d %v", len(cmds), err)
	}
	if v := payloadMap(t, find(cmds, low).Payload)["config"].(map[string]any)["rate_limit"]; v != float64(2) {
		t.Fatalf("a lower job rate was raised to %v", v)
	}
	p := payloadMap(t, find(cmds, none).Payload)
	if p["config"].(map[string]any)["rate_limit"] != float64(20) || p["scanner_config"].(map[string]any)["rate_limit"] != float64(20) {
		t.Fatalf("uncapped job: %v", p)
	}
	if _, ok := p["http_policy"]; ok {
		t.Fatal("http_policy added without a header rule")
	}
	if string(find(cmds, other).Payload) != `{"targets":["owned.example.com"],"config":{"rate_limit":500}}` {
		t.Fatalf("a job no program covers changed: %s", find(cmds, other).Payload)
	}
}

// Outside a testing window the job is not handed out and stays pending.
func TestProgramRules_OutsideWindowWithheld(t *testing.T) {
	for _, path := range handOutPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newProgramFixture(&programRuleSource{err: bp.ErrOutsideWindow}, "v0.19.0")
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, programPayload, nil)
			got, err := path.run(f, c)
			if got != nil {
				t.Fatal("handed out outside the testing window")
			}
			if path.name == "claim by id" && !errors.Is(err, bp.ErrOutsideWindow) {
				t.Fatalf("claim by id: %v", err)
			}
			if st := f.repo.commands[c.ID.String()].Status; st != commanddom.CommandStatusPending {
				t.Fatalf("status %s, want pending", st)
			}
		})
	}
}

// Conflicting programs fail the job once with PROGRAM_RULES_CONFLICT.
func TestProgramRules_ConflictFailsTheJob(t *testing.T) {
	for _, path := range handOutPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newProgramFixture(&programRuleSource{err: bp.ErrRulesConflict}, "v0.19.0")
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, programPayload, nil)
			got, err := path.run(f, c)
			if got != nil {
				t.Fatal("a job with conflicting rules was handed out")
			}
			if path.name == "claim by id" && !errors.Is(err, bp.ErrRulesConflict) {
				t.Fatalf("claim by id: %v", err)
			}
			stored := f.repo.commands[c.ID.String()]
			if stored.Status != commanddom.CommandStatusFailed || !strings.HasPrefix(stored.ErrorMessage, command.FailureProgramRules) {
				t.Fatalf("stored %s %q", stored.Status, stored.ErrorMessage)
			}
			f.steps.wait(t)
			if !strings.Contains(f.steps.calls[0], "|"+command.FailureProgramRules+"|") {
				t.Fatalf("step failure %v", f.steps.calls)
			}
		})
	}
}

// A lookup error withholds (fail closed); the job stays pending.
func TestProgramRules_LookupErrorWithholds(t *testing.T) {
	for _, path := range handOutPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newProgramFixture(&programRuleSource{err: errors.New("db down")}, "v0.19.0")
			c := f.repo.add(f.tenant, commanddom.CommandTypeScan, programPayload, nil)
			if got, _ := path.run(f, c); got != nil {
				t.Fatal("handed out without its program's rules")
			}
			if f.repo.commands[c.ID.String()].Status != commanddom.CommandStatusPending {
				t.Fatal("a lookup error changed the job")
			}
		})
	}
}

// Headers or a User-Agent go only to a sensor whose SDK applies them; an
// older, dev or unknown sensor does not get the job.
func TestProgramRules_SensorMustHonorHeaders(t *testing.T) {
	for _, v := range []string{"v0.18.0", "", "dev", "v0.18.1-0.20261008120000-abcdef123456"} {
		for _, path := range handOutPaths {
			t.Run(v+"/"+path.name, func(t *testing.T) {
				f := newProgramFixture(&programRuleSource{rules: &bp.JobRules{Headers: map[string]string{"X-Bug-Bounty": "jdoe"}}}, v)
				c := f.repo.add(f.tenant, commanddom.CommandTypeScan, programPayload, nil)
				got, err := path.run(f, c)
				if got != nil {
					t.Fatalf("SDK %q got a job needing headers", v)
				}
				if path.name == "claim by id" && !errors.Is(err, command.ErrSensorCannotHonorProgram) {
					t.Fatalf("claim by id: %v", err)
				}
				if f.repo.commands[c.ID.String()].Status != commanddom.CommandStatusPending {
					t.Fatal("the job must wait for a sensor that can honor it")
				}
			})
		}
	}
	f := newProgramFixture(&programRuleSource{rules: &bp.JobRules{UserAgent: "jdoe"}}, "v0.20.1")
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, programPayload, nil)
	if got, err := handOutPaths[0].run(f, c); err != nil || got == nil {
		t.Fatalf("a newer SDK must get the job: %v", err)
	}
}

// Without the option nothing changes.
func TestProgramRules_OffByDefault(t *testing.T) {
	f := newRecheckFixture()
	f.svc = command.NewService(f.repo, newCmdTestLogger())
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, programPayload, nil)
	got, err := handOutPaths[0].run(f, c)
	if err != nil || got == nil || string(got.Payload) != programPayload {
		t.Fatalf("got %v %v", got, err)
	}
}
