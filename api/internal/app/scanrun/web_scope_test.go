package scanrun

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// fakeWebScope answers BuildWebScope with a fixed scope and records the
// targets it was asked about.
type fakeWebScope struct {
	ws      *scopeapp.WebScope
	err     error
	targets []string
}

func (f *fakeWebScope) BuildWebScope(_ context.Context, _ shared.ID, targets []string) (*scopeapp.WebScope, error) {
	f.targets = targets
	return f.ws, f.err
}

func TestApplyWebScope_WebStepsCarryDenyPaths(t *testing.T) {
	f := &fakeWebScope{ws: &scopeapp.WebScope{DenyPaths: []string{"/admin/debug"}}}
	s := &Service{webScope: f}
	payload := map[string]any{"targets": []any{"https://app.example.com"}}
	if err := s.applyWebScope(context.Background(), shared.NewID(), stage.CrawlWeb, payload); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(payload)
	if !strings.Contains(string(b), `"web_scope":{"deny_paths":["/admin/debug"]}`) {
		t.Fatalf("payload = %s, want the deny path", b)
	}
	if len(f.targets) != 1 || f.targets[0] != "https://app.example.com" {
		t.Fatalf("asked about %v", f.targets)
	}

	// A network step never gets one; no rule means no web_scope.
	payload = map[string]any{"targets": []any{"10.0.0.1"}}
	if err := s.applyWebScope(context.Background(), shared.NewID(), stage.ScanPorts, payload); err != nil || payload["web_scope"] != nil {
		t.Fatalf("port scan payload = %v, err %v", payload, err)
	}
	f.ws = nil
	payload = map[string]any{"targets": []any{"https://app.example.com"}}
	if err := s.applyWebScope(context.Background(), shared.NewID(), stage.VulnTemplates, payload); err != nil || payload["web_scope"] != nil {
		t.Fatalf("no rule: payload = %v, err %v", payload, err)
	}
}

func TestApplyWebScope_FailsClosed(t *testing.T) {
	payload := map[string]any{"targets": []any{"https://app.example.com"}}
	if err := (&Service{}).applyWebScope(context.Background(), shared.NewID(), stage.DASTWeb, payload); err == nil {
		t.Fatal("a web step dispatched without the web scope wired")
	}
	s := &Service{webScope: &fakeWebScope{err: errors.New("db down")}}
	if err := s.applyWebScope(context.Background(), shared.NewID(), stage.CrawlWeb, payload); err == nil {
		t.Fatal("a web step dispatched although the exclusions could not be read")
	}
}

type fakeConfined struct {
	has bool
	err error
}

func (f fakeConfined) HasConfinedSensor(context.Context, shared.ID) (bool, error) {
	return f.has, f.err
}

// SECURITY: a web-scoped nuclei job needs a confined sensor; another tool's
// web-scoped job and an unscoped nuclei job do not.
func TestApplyWebScope_NucleiNeedsConfinement(t *testing.T) {
	s := &Service{webScope: &fakeWebScope{ws: &scopeapp.WebScope{DenyPaths: []string{"/admin"}}}}
	for _, tc := range []struct {
		tool  string
		scope bool
		want  bool
	}{{"nuclei", true, true}, {"katana", true, false}, {"nuclei", false, false}} {
		if !tc.scope {
			s.webScope = &fakeWebScope{}
		}
		payload := map[string]any{"scanner": tc.tool, "targets": []any{"https://app.example.com"}}
		if err := s.applyWebScope(context.Background(), shared.NewID(), stage.VulnTemplates, payload); err != nil {
			t.Fatal(err)
		}
		got, _ := payload[command.PayloadKeyRequiredFeatures].([]string)
		if has := len(got) == 1 && got[0] == sensordom.CapabilityNetConfined; has != tc.want {
			t.Errorf("%s (scoped %v): required_features %v, want confinement %v", tc.tool, tc.scope, got, tc.want)
		}
	}
}

// A step whose job needs a confined sensor is refused up front when the
// organization has none; it waits for one otherwise.
func TestRequireConfinedSensor(t *testing.T) {
	need := map[string]any{command.PayloadKeyRequiredFeatures: []string{sensordom.CapabilityNetConfined}}
	tenant := shared.NewID()

	err := (&Service{confined: fakeConfined{has: false}}).requireConfinedSensor(context.Background(), tenant, need)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != scanrundom.FailureNoConfinedSensor {
		t.Fatalf("no confined sensor: err %v, want %s", err, scanrundom.FailureNoConfinedSensor)
	}
	if scanrundom.ClassOf(de.Code).Retryable() {
		t.Fatal("NO_CONFINED_SENSOR must not be retried")
	}
	if err := (&Service{confined: fakeConfined{has: true}}).requireConfinedSensor(context.Background(), tenant, need); err != nil {
		t.Fatalf("a confined sensor exists: %v", err)
	}
	if err := (&Service{confined: fakeConfined{has: false}}).requireConfinedSensor(context.Background(), tenant, map[string]any{}); err != nil {
		t.Fatalf("a job without the need: %v", err)
	}
	if err := (&Service{confined: fakeConfined{err: errors.New("db down")}}).requireConfinedSensor(context.Background(), tenant, need); err == nil || errors.As(err, &de) && de.Code == scanrundom.FailureNoConfinedSensor {
		t.Fatalf("lookup error: %v, want a plain error (not a permanent refusal)", err)
	}
}
