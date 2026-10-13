package scope

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeWebScope answers with a fixed scope and records what it was asked.
type fakeWebScope struct {
	ws      *WebScope
	err     error
	calls   int
	tenant  shared.ID
	targets []string
}

func (f *fakeWebScope) BuildWebScope(_ context.Context, tenantID shared.ID, targets []string) (*WebScope, error) {
	f.calls++
	f.tenant, f.targets = tenantID, targets
	return f.ws, f.err
}

type fakeConfined struct {
	has bool
	err error
}

func (f fakeConfined) HasConfinedSensor(context.Context, shared.ID) (bool, error) {
	return f.has, f.err
}

func newCmd(t *testing.T, typ commanddom.CommandType, payload map[string]any) *commanddom.Command {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	cmd, err := commanddom.NewCommand(shared.NewID(), typ, commanddom.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func payloadOf(t *testing.T, cmd *commanddom.Command) map[string]any {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func denyPaths(p map[string]any) []string {
	ws, _ := p[commanddom.PayloadKeyWebScope].(map[string]any)
	var out []string
	for _, v := range ws["deny_paths"].([]any) {
		out = append(out, v.(string))
	}
	return out
}

var adminScope = &WebScope{DenyPaths: []string{"/admin"}}

// SECURITY: a quick scan (a single-scanner job with no workflow stage) and
// a step outside the stage catalog carry the web scope: the tool or the
// capability decides, not the stage of the step.
func TestWebJobGuard_EveryWebScanJobCarriesTheScope(t *testing.T) {
	for name, payload := range map[string]map[string]any{
		"quick scan nuclei":           {"scanner": "nuclei", "scanner_name": "nuclei", "step_key": "quick_scan", "targets": []string{"https://app.example.com"}},
		"crawler":                     {"scanner": "katana", "target": "https://app.example.com"},
		"dast":                        {"scanner": "ZAP", "targets": []string{"https://app.example.com"}},
		"preferred tool only":         {"preferred_tool": "nuclei", "targets": []string{"https://app.example.com"}},
		"tenant tool, web capability": {"scanner": "my-crawler", "required_capabilities": []string{"crawl.web"}, "targets": []string{"https://app.example.com"}},
		"capability job":              {"scanner": "my-templates", "capability": "vuln.templates@1", "targets": []string{"https://app.example.com"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeWebScope{ws: adminScope}
			cmd := newCmd(t, commanddom.CommandTypeScan, payload)
			if err := NewWebJobGuard(f, nil).GuardCreate(context.Background(), cmd); err != nil {
				t.Fatal(err)
			}
			if got := denyPaths(payloadOf(t, cmd)); !slices.Equal(got, []string{"/admin"}) {
				t.Fatalf("deny_paths = %v, want [/admin]; payload %s", got, cmd.Payload)
			}
			if !f.tenant.Equals(cmd.TenantID) {
				t.Fatal("the scope was built for another tenant than the command's")
			}
			if !slices.Equal(f.targets, []string{"https://app.example.com"}) {
				t.Fatalf("asked about %v", f.targets)
			}
		})
	}
}

// A job that requests no web paths is left alone, and the lookup is not
// even made.
func TestWebJobGuard_NonWebJobsUntouched(t *testing.T) {
	f := &fakeWebScope{ws: adminScope}
	for _, cmd := range []*commanddom.Command{
		newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "httpx", "targets": []string{"app.example.com"}}),
		newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "naabu", "targets": []string{"10.0.0.1"}}),
		newCmd(t, commanddom.CommandTypeValidate, map[string]any{"executor_kind": "safe-check", "target": map[string]any{"address": "app.example.com"}}),
		newCmd(t, commanddom.CommandTypeRetest, map[string]any{"scanner": "trivy", "targets": []string{"repo"}}),
		newCmd(t, commanddom.CommandTypeHealthCheck, map[string]any{"scanner": "nuclei"}),
	} {
		before := string(cmd.Payload)
		if err := NewWebJobGuard(f, nil).GuardCreate(context.Background(), cmd); err != nil {
			t.Fatalf("%s: %v", before, err)
		}
		if string(cmd.Payload) != before {
			t.Fatalf("payload changed: %s -> %s", before, cmd.Payload)
		}
	}
	if f.calls != 0 {
		t.Fatalf("looked up the web scope %d time(s) for jobs without web requests", f.calls)
	}
}

// SECURITY: fail closed. A failed lookup, an unwired builder and an unwired
// guard all refuse the job.
func TestWebJobGuard_FailsClosed(t *testing.T) {
	job := func() *commanddom.Command {
		return newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "nuclei", "targets": []string{"https://app.example.com"}})
	}
	if err := NewWebJobGuard(&fakeWebScope{err: errors.New("db down")}, nil).GuardCreate(context.Background(), job()); err == nil {
		t.Fatal("a web job was let through although the exclusions could not be read")
	}
	if err := NewWebJobGuard(nil, nil).GuardCreate(context.Background(), job()); !errors.Is(err, commanddom.ErrWebScopeUnwired) {
		t.Fatalf("no builder: err = %v, want ErrWebScopeUnwired", err)
	}
	var g *WebJobGuard
	if err := g.GuardCreate(context.Background(), job()); !errors.Is(err, commanddom.ErrWebScopeUnwired) {
		t.Fatalf("nil guard: err = %v, want ErrWebScopeUnwired", err)
	}
	if err := commanddom.GuardUnwired(job()); !errors.Is(err, commanddom.ErrWebScopeUnwired) {
		t.Fatalf("GuardUnwired: %v", err)
	}
	if err := commanddom.GuardUnwired(newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "httpx"})); err != nil {
		t.Fatalf("GuardUnwired refused a job without web requests: %v", err)
	}
}

// SECURITY: the platform is the only author of web_scope. A caller's own
// value (POST /api/v1/commands) is replaced, or removed when no rule
// applies.
func TestWebJobGuard_CallerScopeReplaced(t *testing.T) {
	forged := map[string]any{"deny_paths": []string{"/nothing"}, "methods": []string{"GET", "POST", "DELETE"}}
	cmd := newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "katana", "targets": []string{"https://app.example.com"}, "web_scope": forged})
	if err := NewWebJobGuard(&fakeWebScope{ws: adminScope}, nil).GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cmd.Payload), "/nothing") || !slices.Equal(denyPaths(payloadOf(t, cmd)), []string{"/admin"}) {
		t.Fatalf("payload %s, want the platform's scope only", cmd.Payload)
	}
	cmd = newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "katana", "targets": []string{"https://app.example.com"}, "web_scope": forged})
	if err := NewWebJobGuard(&fakeWebScope{}, nil).GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if _, ok := payloadOf(t, cmd)[commanddom.PayloadKeyWebScope]; ok {
		t.Fatalf("payload %s keeps the caller's web_scope", cmd.Payload)
	}
}

// The payload's other fields survive the rewrite as written.
func TestWebJobGuard_KeepsPayload(t *testing.T) {
	cmd := newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "katana", "targets": []string{"https://app.example.com"},
		"timeout_seconds": 9007199254740993, "config": map[string]any{"depth": 3}})
	if err := NewWebJobGuard(&fakeWebScope{ws: adminScope}, nil).GuardCreate(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cmd.Payload), `"timeout_seconds":9007199254740993`) || !strings.Contains(string(cmd.Payload), `"depth":3`) {
		t.Fatalf("payload %s lost a field", cmd.Payload)
	}
}

// SECURITY: a web-scoped nuclei job needs a confined sensor, merged into the
// features the payload already asks for; another tool's web-scoped job and
// an unscoped nuclei job do not.
func TestWebJobGuard_NucleiNeedsConfinement(t *testing.T) {
	for _, tc := range []struct {
		tool  string
		scope *WebScope
		want  bool
	}{{"nuclei", adminScope, true}, {"katana", adminScope, false}, {"nuclei", nil, false}} {
		cmd := newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": tc.tool, "targets": []string{"https://app.example.com"},
			commanddom.PayloadKeyRequiredFeatures: []string{"other@1"}})
		if err := NewWebJobGuard(&fakeWebScope{ws: tc.scope}, fakeConfined{has: true}).GuardCreate(context.Background(), cmd); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, v := range payloadOf(t, cmd)[commanddom.PayloadKeyRequiredFeatures].([]any) {
			got = append(got, v.(string))
		}
		if has := slices.Contains(got, sensordom.CapabilityNetConfined); has != tc.want || !slices.Contains(got, "other@1") {
			t.Errorf("%s (scoped %v): required_features %v, want confinement %v and the existing feature", tc.tool, tc.scope != nil, got, tc.want)
		}
	}
}

// A job that needs a confined sensor is refused up front when the
// organization has none; a lookup error is not a permanent refusal.
func TestWebJobGuard_NoConfinedSensor(t *testing.T) {
	job := func() *commanddom.Command {
		return newCmd(t, commanddom.CommandTypeScan, map[string]any{"scanner": "nuclei", "targets": []string{"https://app.example.com"}})
	}
	err := NewWebJobGuard(&fakeWebScope{ws: adminScope}, fakeConfined{}).GuardCreate(context.Background(), job())
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != scanrundom.FailureNoConfinedSensor {
		t.Fatalf("no confined sensor: err %v, want %s", err, scanrundom.FailureNoConfinedSensor)
	}
	if scanrundom.ClassOf(de.Code).Retryable() {
		t.Fatal("NO_CONFINED_SENSOR must not be retried")
	}
	err = NewWebJobGuard(&fakeWebScope{ws: adminScope}, fakeConfined{err: errors.New("db down")}).GuardCreate(context.Background(), job())
	if err == nil || errors.As(err, &de) && de.Code == scanrundom.FailureNoConfinedSensor {
		t.Fatalf("lookup error: %v, want a plain error", err)
	}
	if err := NewWebJobGuard(&fakeWebScope{}, fakeConfined{}).GuardCreate(context.Background(), job()); err != nil {
		t.Fatalf("an unscoped nuclei job needs no confined sensor: %v", err)
	}
}

// SECURITY: a nuclei validation or retest cannot carry a web scope to the
// sensor yet, so it is refused when a path exclusion applies to its
// target, and dispatched unchanged when none does.
func TestWebJobGuard_ValidateAndRetest(t *testing.T) {
	for name, mk := range map[string]func() *commanddom.Command{
		"validate": func() *commanddom.Command {
			return newCmd(t, commanddom.CommandTypeValidate, map[string]any{"executor_kind": "nuclei", "template_id": "x",
				"target": map[string]any{"address": "https://app.example.com/login"}})
		},
		"retest": func() *commanddom.Command {
			return newCmd(t, commanddom.CommandTypeRetest, map[string]any{"scanner": "nuclei", "targets": []string{"https://app.example.com/login"}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeWebScope{ws: adminScope}
			err := NewWebJobGuard(f, fakeConfined{has: true}).GuardCreate(context.Background(), mk())
			var de *shared.DomainError
			if !errors.As(err, &de) || de.Code != scanrundom.FailureWebScopeUnsupported || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want %s", err, scanrundom.FailureWebScopeUnsupported)
			}
			if !slices.Equal(f.targets, []string{"https://app.example.com/login"}) {
				t.Fatalf("asked about %v", f.targets)
			}
			cmd := mk()
			before := string(cmd.Payload)
			if err := NewWebJobGuard(&fakeWebScope{}, nil).GuardCreate(context.Background(), cmd); err != nil || string(cmd.Payload) != before {
				t.Fatalf("no rule: err %v, payload %s", err, cmd.Payload)
			}
			if err := NewWebJobGuard(&fakeWebScope{err: errors.New("db down")}, nil).GuardCreate(context.Background(), mk()); err == nil {
				t.Fatal("lookup error let the job through")
			}
		})
	}
}
