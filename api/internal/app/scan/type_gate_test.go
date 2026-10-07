package scan

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stubTools answers GetByName from a fixed set; every other method panics.
type stubTools struct {
	tool.Repository
	tools map[string]*tool.Tool
	err   error
}

func (s *stubTools) GetByName(_ context.Context, _ shared.ID, name string) (*tool.Tool, error) {
	if s.err != nil {
		return nil, s.err
	}
	if t, ok := s.tools[name]; ok {
		return t, nil
	}
	return nil, shared.ErrNotFound
}

var gateTools = &stubTools{tools: map[string]*tool.Tool{
	"zap":      {Name: "zap", SupportedTargets: []string{"url"}},
	"semgrep":  {Name: "semgrep", SupportedTargets: []string{"repository", "file"}},
	"freeform": {Name: "freeform"}, // declares no target type: nothing can be decided
}}

// typedMembersRepo serves group members with their stored (type, sub_type).
type typedMembersRepo struct {
	assetgroup.Repository
	members []*assetgroup.ScanMember
}

func (r *typedMembersRepo) ListScanMembers(_ context.Context, q assetgroup.ScanMemberQuery) (*assetgroup.ScanMemberPage, error) {
	if !q.AfterID.IsZero() {
		return &assetgroup.ScanMemberPage{}, nil
	}
	return &assetgroup.ScanMemberPage{Members: r.members}, nil
}

func member(name string, t asset.AssetType, sub string) *assetgroup.ScanMember {
	return &assetgroup.ScanMember{ID: shared.NewID(), Name: name, Type: string(t), SubType: sub}
}

// RFC-042 §6.3.8 O6: a single-scanner run hands its scanner only the group
// members whose stored type the scanner can scan. Before, ZAP was handed a
// repository and a mobile app and the run only reported them "skipped".
func TestResolveScanTargets_LeavesOutTypesTheScannerCannotScan(t *testing.T) {
	svc := &Service{
		assetGroupRepo: &typedMembersRepo{members: []*assetgroup.ScanMember{
			member("https://app.example.com", asset.AssetTypeApplication, "website"),
			member("https://api.example.com", asset.AssetTypeApplication, "api"),
			member("github.com/acme/app", asset.AssetTypeRepository, ""),
			member("com.acme.app", asset.AssetTypeApplication, "mobile_app"),
			member("mystery", asset.AssetTypeUnclassified, ""), // undecidable: kept
			member("legacy", asset.AssetType("ip"), ""),        // unknown legacy code: kept
			member("https://old.example.com", "website", ""),   // legacy alias row: (application, website)
		}},
		toolRepo: gateTools,
		logger:   logger.NewNop(),
	}
	sc := testScan("zap")
	sc.AssetGroupID = shared.NewID()

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://app.example.com", "https://api.example.com", "mystery", "legacy", "https://old.example.com"}
	if !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("targets = %v, want %v", got.Targets, want)
	}
	if got.Incompatible != 2 {
		t.Fatalf("incompatible = %d, want 2", got.Incompatible)
	}
	if !strings.Contains(got.IncompatibleReason, "1 application/mobile_app") ||
		!strings.Contains(got.IncompatibleReason, "1 repository") ||
		!strings.Contains(got.IncompatibleReason, "url") {
		t.Fatalf("reason = %q", got.IncompatibleReason)
	}
	if got.TargetTypes["https://app.example.com"] != "application/website" || got.TargetTypes["mystery"] != "unclassified" {
		t.Fatalf("target types = %v", got.TargetTypes)
	}
	if _, typed := got.TargetTypes["github.com/acme/app"]; typed {
		t.Fatal("a refused member must not be dispatched or typed")
	}
	found := false
	for _, w := range got.Warnings {
		found = found || strings.Contains(w, "2 asset(s) in the group(s) were skipped")
	}
	if !found {
		t.Fatalf("warnings = %v", got.Warnings)
	}
}

// A run with nothing its scanner can scan is refused with a clear error
// (400), not dispatched with an empty or wrong target list.
func TestRecordResolvedTargets_NothingCompatibleIsRefused(t *testing.T) {
	svc := &Service{
		assetGroupRepo: &typedMembersRepo{members: []*assetgroup.ScanMember{
			member("github.com/acme/app", asset.AssetTypeRepository, ""),
		}},
		toolRepo: gateTools,
		logger:   logger.NewNop(),
	}
	sc := testScan("zap")
	sc.AssetGroupID = shared.NewID()
	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	err = recordResolvedTargets(sc, got, map[string]any{})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != codeNoCompatibleTargets || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want %s (validation)", err, codeNoCompatibleTargets)
	}
	if !strings.Contains(err.Error(), "zap cannot scan 1 repository") {
		t.Fatalf("message must name the scanner and the type: %v", err)
	}
}

// The gate cannot be decided for a tool without target types, a tool the
// platform does not know, or a workflow run (no scanner): nothing is left out.
func TestResolveScanTargets_UndecidableToolsKeepEveryMember(t *testing.T) {
	for _, scanner := range []string{"freeform", "not-a-tool", ""} {
		svc := &Service{
			assetGroupRepo: &typedMembersRepo{members: []*assetgroup.ScanMember{
				member("github.com/acme/app", asset.AssetTypeRepository, ""),
			}},
			toolRepo: gateTools,
			logger:   logger.NewNop(),
		}
		sc := testScan(scanner)
		sc.AssetGroupID = shared.NewID()
		got, err := svc.resolveScanTargets(context.Background(), sc)
		if err != nil {
			t.Fatalf("%q: %v", scanner, err)
		}
		if len(got.Targets) != 1 || got.Incompatible != 0 {
			t.Fatalf("%q: targets %v incompatible %d", scanner, got.Targets, got.Incompatible)
		}
		if got.TargetTypes["github.com/acme/app"] != "repository" {
			t.Fatalf("%q: a workflow step needs the member's type: %v", scanner, got.TargetTypes)
		}
	}
}

// A failed tool lookup stops the dispatch (fail closed) rather than handing
// the scanner unchecked targets.
func TestResolveScanTargets_ToolLookupErrorFailsClosed(t *testing.T) {
	svc := &Service{
		assetGroupRepo: &typedMembersRepo{},
		toolRepo:       &stubTools{err: errors.New("db down")},
		logger:         logger.NewNop(),
	}
	sc := testScan("zap", "https://app.example.com")
	if _, err := svc.resolveScanTargets(context.Background(), sc); err == nil {
		t.Fatal("expected an error")
	}
}

// Each workflow step gets only the run's typed targets its own tool can
// scan; direct (untyped) targets keep the checks they always had.
func TestFilterStepTargets(t *testing.T) {
	svc := &Service{toolRepo: gateTools, logger: logger.NewNop()}
	rc := map[string]any{
		"targets": []string{"https://app.example.com", "github.com/acme/app", "typed-by-hand.example.com"},
		RunContextKeyTargetTypes: map[string]string{
			"https://app.example.com": "application/website",
			"github.com/acme/app":     "repository",
		},
	}
	// Survives the JSON round trip of a stored run.
	raw, _ := json.Marshal(rc)
	var stored map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	for name, ctx := range map[string]map[string]any{"fresh": rc, "stored": stored} {
		st, err := svc.FilterStepTargets(context.Background(), shared.ID{}, "zap", ctx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(st.Targets, []string{"https://app.example.com", "typed-by-hand.example.com"}) || st.Refused != 1 {
			t.Fatalf("%s zap: %+v", name, st)
		}
		st, err = svc.FilterStepTargets(context.Background(), shared.ID{}, "semgrep", ctx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(st.Targets, []string{"github.com/acme/app", "typed-by-hand.example.com"}) {
			t.Fatalf("%s semgrep: %+v", name, st)
		}
	}

	// Every target refused: the step must not reach a sensor.
	only := map[string]any{
		"targets":                []string{"github.com/acme/app"},
		RunContextKeyTargetTypes: map[string]string{"github.com/acme/app": "repository"},
	}
	_, err := svc.FilterStepTargets(context.Background(), shared.ID{}, "zap", only)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != codeIncompatibleTargets || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want %s", err, codeIncompatibleTargets)
	}

	// No typed targets: unchanged.
	st, err := svc.FilterStepTargets(context.Background(), shared.ID{}, "zap", map[string]any{"targets": []string{"x"}})
	if err != nil || !reflect.DeepEqual(st.Targets, []string{"x"}) {
		t.Fatalf("untyped: %+v %v", st, err)
	}
}

// The step context a sensor receives carries the step's targets and never
// the platform's type bookkeeping.
func TestStepRunContext(t *testing.T) {
	rc := map[string]any{
		"scan_id":                "s",
		"targets":                []string{"a", "b"},
		RunContextKeyTargetTypes: map[string]string{"a": "host"},
	}
	got := StepRunContext(rc, &StepTargets{Targets: []string{"a"}})
	if _, leaked := got[RunContextKeyTargetTypes]; leaked {
		t.Fatal("target_types must not reach a sensor")
	}
	if !reflect.DeepEqual(got["targets"], []string{"a"}) || got["scan_id"] != "s" {
		t.Fatalf("context = %v", got)
	}
	if _, still := rc[RunContextKeyTargetTypes]; !still {
		t.Fatal("the run's own context must not be changed")
	}
	if got := StepRunContext(rc, nil); !reflect.DeepEqual(got["targets"], []string{"a", "b"}) {
		t.Fatalf("nil step targets keep the run's: %v", got)
	}
}

// The step payload carries the step's own targets.
func TestStepCommandPayload_StepTargets(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{
		"targets":                []string{"a", "b"},
		RunContextKeyTargetTypes: map[string]string{"a": "host", "b": "repository"},
	}}
	p, err := StepCommandPayload(run, &scanworkflow.Step{ID: shared.NewID(), StepKey: "s", Tool: "nmap"}, "nmap", "sr", &StepTargets{Targets: []string{"a"}, Refused: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p["targets"], []string{"a"}) {
		t.Fatalf("targets = %v", p["targets"])
	}
	ctx, _ := p["context"].(map[string]any)
	if _, leaked := ctx[RunContextKeyTargetTypes]; leaked || !reflect.DeepEqual(ctx["targets"], []string{"a"}) {
		t.Fatalf("context = %v", ctx)
	}
}
