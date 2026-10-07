package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
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
