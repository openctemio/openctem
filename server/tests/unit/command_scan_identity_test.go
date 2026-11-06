package unit

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanident"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scan identification markers at delivery (docs/architecture/
// scan-identification.md): the platform layer and the organization's merge
// into http_policy; a program goes over both but never over an enforced
// platform header; a merged set over the sensor's cap fails the job.

type platformIdentity struct{ layer scanident.PlatformLayer }

func (p platformIdentity) PlatformLayer(context.Context) (scanident.PlatformLayer, error) {
	return p.layer, nil
}

var testPlatformLayer = scanident.PlatformLayer{UserAgent: "openctem-scanner", Headers: []scanident.Header{
	{Name: "X-Operator", Value: "saas", Enforced: true},
	{Name: "X-Env", Value: "prod"},
}}

func newIdentityFixture(src *programRuleSource, org sensor.ToolHTTPPolicy) *recheckFixture {
	f := newRecheckFixture()
	lookup := policySensorLookup{sensors: map[shared.ID]*sensor.Sensor{f.sensor: identitySensor(f.sensor, f.tenant, true)}}
	opts := []command.Option{command.WithSensorLookup(lookup), command.WithHTTPPolicy(orgHTTPPolicy{org}),
		command.WithPlatformIdentity(platformIdentity{testPlatformLayer})}
	if src != nil {
		opts = append(opts, command.WithProgramRules(src))
	}
	f.svc = command.NewService(f.repo, newCmdTestLogger(), opts...)
	f.svc.SetFailureObserver(f.steps)
	return f
}

func TestScanIdentity_MergedIntoEveryJob(t *testing.T) {
	org := sensor.ToolHTTPPolicy{UserAgent: "corp-scan", Headers: map[string]string{"ATTT": "is-here", "x-env": "uat", "x-operator": "mine"}}
	for _, typ := range []commanddom.CommandType{commanddom.CommandTypeScan, commanddom.CommandTypeRetest} {
		for _, path := range handOutPaths[:2] {
			t.Run(string(typ)+"/"+path.name, func(t *testing.T) {
				f := newIdentityFixture(nil, org)
				c := f.repo.add(f.tenant, typ, `{"scanner":"nuclei","targets":["a.example"],"http_policy":{"headers":{"X-Creator":"1"}}}`, nil)
				got, err := path.run(f, c)
				if err != nil || got == nil {
					t.Fatalf("hand-out: %v %v", got, err)
				}
				pol := payloadMap(t, got.Payload)["http_policy"].(map[string]any)
				h := pol["headers"].(map[string]any)
				if h["X-Operator"] != "saas" || h["x-env"] != "uat" || h["ATTT"] != "is-here" || len(h) != 3 {
					t.Fatalf("headers %v", h)
				}
				if pol["user_agent"] != "corp-scan" || pol["user_agent_locked"] != nil {
					t.Fatalf("ua %v", pol)
				}
				if l, _ := pol["locked_headers"].([]any); len(l) != 1 || l[0] != "X-Operator" {
					t.Fatalf("locked %v", pol["locked_headers"])
				}
			})
		}
	}
}

// A program's headers and User-Agent win over the organization, never over
// an enforced platform header; its names become locked for the sensor.
func TestScanIdentity_ProgramKeepsEnforcedHeaders(t *testing.T) {
	src := &programRuleSource{rules: &bp.JobRules{Headers: map[string]string{"X-Bug-Bounty": "jdoe", "x-operator": "prog"}, UserAgent: "jdoe-research"}}
	f := newIdentityFixture(src, sensor.ToolHTTPPolicy{Headers: map[string]string{"X-Bug-Bounty": "org"}})
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, programPayload, nil)
	got, err := handOutPaths[0].run(f, c)
	if err != nil || got == nil {
		t.Fatalf("hand-out: %v %v", got, err)
	}
	pol := payloadMap(t, got.Payload)["http_policy"].(map[string]any)
	h := pol["headers"].(map[string]any)
	if h["X-Operator"] != "saas" || h["X-Bug-Bounty"] != "jdoe" || h["x-operator"] != nil || h["X-Env"] != "prod" {
		t.Fatalf("headers %v", h)
	}
	if pol["user_agent"] != "jdoe-research" || pol["user_agent_locked"] != true {
		t.Fatalf("ua %v", pol)
	}
	if l, _ := pol["locked_headers"].([]any); len(l) != 2 {
		t.Fatalf("locked %v", pol["locked_headers"])
	}
}

// Program headers that, with the platform's and the organization's, exceed
// what a sensor accepts fail the job instead of sending a job the sensor
// would refuse.
func TestScanIdentity_OverflowFailsTheJob(t *testing.T) {
	many := map[string]string{}
	for i := 0; i < 9; i++ {
		many["X-P"+string(rune('a'+i))] = "v"
	}
	f := newIdentityFixture(&programRuleSource{rules: &bp.JobRules{Headers: many}}, sensor.ToolHTTPPolicy{})
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, programPayload, nil)
	if got, _ := handOutPaths[0].run(f, c); got != nil {
		t.Fatal("a job over the header cap was handed out")
	}
	stored := f.repo.commands[c.ID.String()]
	if stored.Status != commanddom.CommandStatusFailed || !strings.HasPrefix(stored.ErrorMessage, command.FailureProgramRules) {
		t.Fatalf("stored %s %q", stored.Status, stored.ErrorMessage)
	}
}
