package unit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Dynamic target selectors (RFC-068). A wildcard domain (*.x) and an
// inventory-mode CIDR are expanded from the inventory at every run start,
// never at save, and every name they add goes through the one dispatch gate
// as the inventory asset it is. A pattern never reaches a scanner as a host:
// live, a nuclei scan was dispatched against "*.example.co.uk" and refused
// by the sensor ("cannot resolve").

func wildcardCode(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

// fakeSelectorAssets is the inventory behind the selectors: names per root
// and addresses per range, of one tenant. It records every query.
type fakeSelectorAssets struct {
	tenant  shared.ID
	byRoot  map[string][]string
	byCIDR  map[string][]string
	ids     map[string]shared.ID
	queries []scan.SelectorQuery
	err     error
}

func newFakeSelectorAssets(tenant shared.ID) *fakeSelectorAssets {
	return &fakeSelectorAssets{tenant: tenant, byRoot: map[string][]string{}, byCIDR: map[string][]string{}, ids: map[string]shared.ID{}}
}

func (f *fakeSelectorAssets) id(name string) shared.ID {
	if id, ok := f.ids[name]; ok {
		return id
	}
	id := shared.NewID()
	f.ids[name] = id
	return id
}

func (f *fakeSelectorAssets) ListSelectorAssets(_ context.Context, q scan.SelectorQuery) ([]*assetgroup.ScanMember, error) {
	f.queries = append(f.queries, q)
	if f.err != nil {
		return nil, f.err
	}
	// Another tenant's inventory is empty: the read is pinned to the tenant.
	if q.TenantID != f.tenant {
		return nil, nil
	}
	var names []string
	typ, sub := "domain", ""
	if q.UnderDomain != "" {
		names = f.byRoot[q.UnderDomain]
		sub = "subdomain"
	} else {
		names = f.byCIDR[q.InCIDR]
		typ = "ip_address"
	}
	out := make([]*assetgroup.ScanMember, 0, len(names))
	for _, n := range names {
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
		out = append(out, &assetgroup.ScanMember{ID: f.id(n), Name: n, Type: typ, SubType: sub, Status: "active"})
	}
	return out, nil
}

// dispatchedTargets is every target in the run's commands.
func dispatchedTargets(t *testing.T, deps *testScanServiceDeps) []string {
	t.Helper()
	var out []string
	for _, c := range deps.commandRepo.commands {
		var p map[string]any
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			t.Fatal(err)
		}
		ts, _ := p["targets"].([]any)
		for _, v := range ts {
			out = append(out, fmt.Sprint(v))
		}
		if len(ts) == 0 {
			if v, ok := p["target"].(string); ok {
				out = append(out, v)
			}
		}
	}
	for _, v := range out {
		if strings.HasPrefix(v, "*.") {
			t.Errorf("a wildcard pattern reached a scanner: %s", v)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// directScan stores a single-scanner scan with only direct targets.
func directScan(deps *testScanServiceDeps, tenantID shared.ID, tool string, targets ...string) *scan.Scan {
	sc := createTestScanInRepo(deps, tenantID, "dyn-"+tool, scan.ScanTypeSingle)
	_ = sc.SetSingleScanner(tool, map[string]any{}, 1)
	sc.SetTargets(targets)
	sc.AssetGroupID = shared.ID{}
	sc.AssetGroupIDs = nil
	return sc
}

func onlyRun(t *testing.T, deps *testScanServiceDeps) map[string]any {
	t.Helper()
	if len(deps.runRepo.runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(deps.runRepo.runs))
	}
	for _, r := range deps.runRepo.runs {
		return r.Context
	}
	return nil
}

func TestWildcardTarget_CreateKeepsThePatternForAnyTool(t *testing.T) {
	for _, tool := range []string{"nuclei", "subfinder"} {
		t.Run(tool, func(t *testing.T) {
			svc, deps := newTestScanService()
			deps.toolRepo.addTool(tool, true)
			sc, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
				TenantID: shared.NewID().String(), Name: "wild", ScanType: "single",
				ScannerName: tool, Targets: []string{"*.example.com"},
				TargetOptions: &scan.TargetOptions{SeenWithinDays: 30},
			})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if len(sc.Targets) != 1 || sc.Targets[0] != "*.example.com" {
				t.Errorf("stored targets = %v, want the pattern as written", sc.Targets)
			}
			if sc.TargetOptions.SeenWithinDays != 30 {
				t.Errorf("target options = %+v, want seen_within_days 30", sc.TargetOptions)
			}
		})
	}
}

// A root nobody may cover is refused when the scan is saved.
func TestWildcardTarget_CreateRefusesSharedRoots(t *testing.T) {
	for _, pattern := range []string{"*.com", "*.co.uk", "*.amazonaws.com", "*.*.example.com", "*.exa mple.com"} {
		t.Run(pattern, func(t *testing.T) {
			svc, deps := newTestScanService()
			deps.toolRepo.addTool("nuclei", true)
			_, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
				TenantID: shared.NewID().String(), Name: "wild", ScanType: "single",
				ScannerName: "nuclei", Targets: []string{pattern},
			})
			if err == nil {
				t.Fatalf("%s was accepted", pattern)
			}
			if len(deps.scanRepo.scans) != 0 {
				t.Error("the refused scan was stored")
			}
		})
	}
}

func TestTargetOptions_CreateRefusesBadValues(t *testing.T) {
	for _, o := range []scan.TargetOptions{{CIDRMode: "everything"}, {SeenWithinDays: -1}, {SeenWithinDays: 366}} {
		svc, deps := newTestScanService()
		deps.toolRepo.addTool("nuclei", true)
		_, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
			TenantID: shared.NewID().String(), Name: "opts", ScanType: "single",
			ScannerName: "nuclei", Targets: []string{"example.com"}, TargetOptions: &o,
		})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("options %+v: err = %v, want a validation error", o, err)
		}
	}
}

// The run of an active tool scans the apex and every name the inventory
// holds under it now; the stored scan keeps the pattern.
func TestWildcardTarget_RunExpandsFromTheInventory(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["example.com"] = []string{"api.example.com", "www.example.com", "example.com"}
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)
	sc := directScan(deps, tenantID, "nuclei", "*.Example.com", "other.net")
	sc.TargetOptions = scan.TargetOptions{SeenWithinDays: 14, IncludeStale: true}

	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	}); err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	got := dispatchedTargets(t, deps)
	want := []string{"api.example.com", "example.com", "other.net", "www.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("dispatched %v, want %v", got, want)
	}
	if len(inv.queries) != 1 {
		t.Fatalf("queries = %d, want 1", len(inv.queries))
	}
	q := inv.queries[0]
	if q.TenantID != tenantID || q.UnderDomain != "example.com" || !q.IncludeStale || q.SeenSince == nil {
		t.Errorf("query = %+v: want the scan's tenant, the lower-case root and its options", q)
	}
	if q.Limit != scanservice.MaxSelectorTargets+1 {
		t.Errorf("limit = %d, want the cap + 1", q.Limit)
	}
	if stored := deps.scanRepo.scans[sc.ID.String()]; stored.Targets[0] != "*.Example.com" {
		t.Errorf("stored targets rewritten to %v", stored.Targets)
	}

	ctx := onlyRun(t, deps)
	exp, ok := ctx[scanservice.RunContextKeyTargetExpansion].([]scanservice.TargetExpansion)
	if !ok || len(exp) != 1 || exp[0].Selector != "*.Example.com" || exp[0].Kind != scanservice.SelectorKindWildcard || exp[0].Matched != 3 {
		t.Errorf("run expansion = %#v, want one wildcard entry with 3 matches", ctx[scanservice.RunContextKeyTargetExpansion])
	}
	// The expansion record never reaches a sensor.
	for _, c := range deps.commandRepo.commands {
		if strings.Contains(string(c.Payload), scanservice.RunContextKeyTargetExpansion) ||
			strings.Contains(string(c.Payload), scanservice.RunContextKeySelectorRoots) {
			t.Errorf("payload carries platform bookkeeping: %s", c.Payload)
		}
	}
}

// A second run sees what was discovered after the first.
func TestWildcardTarget_EachRunReresolves(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["example.com"] = []string{"a.example.com"}
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)
	sc := directScan(deps, tenantID, "nuclei", "*.example.com")

	trigger := func() []string {
		clear(deps.commandRepo.commands)
		if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
			TenantID: tenantID.String(), ScanID: sc.ID.String(),
		}); err != nil {
			t.Fatalf("TriggerScan: %v", err)
		}
		return dispatchedTargets(t, deps)
	}
	if got := trigger(); !slices.Equal(got, []string{"a.example.com", "example.com"}) {
		t.Fatalf("first run: %v", got)
	}
	inv.byRoot["example.com"] = append(inv.byRoot["example.com"], "new.example.com")
	if got := trigger(); !slices.Equal(got, []string{"a.example.com", "example.com", "new.example.com"}) {
		t.Errorf("second run: %v, want the name found since", got)
	}
}

// Without the inventory reader the run is refused, never narrowed to the
// apex in silence.
func TestWildcardTarget_RunRefusedWithoutTheInventory(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	sc := directScan(deps, tenantID, "nuclei", "*.example.com")
	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	})
	if wildcardCode(err) != scanservice.CodeSelectorUnavailable {
		t.Fatalf("err = %v, want %s", err, scanservice.CodeSelectorUnavailable)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Errorf("%d command(s) dispatched", len(deps.commandRepo.commands))
	}
}

func TestWildcardTarget_RunRefusedOnInventoryError(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.err = errors.New("db down")
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)
	sc := directScan(deps, tenantID, "nuclei", "*.example.com")
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	}); err == nil {
		t.Fatal("a failed inventory read dispatched the run")
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Errorf("%d command(s) dispatched", len(deps.commandRepo.commands))
	}
}

// Subdomain discovery gets the apex alone; the inventory is not read.
func TestWildcardTarget_TriggerHandsDiscoveryToolTheRoot(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["example.com"] = []string{"api.example.com"}
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("subfinder", true)
	sc := directScan(deps, tenantID, "subfinder", "*.Example.com", "example.com")
	_ = sc.SetSingleScanner("subfinder", map[string]any{"targets": []any{"*.Example.com"}}, 1)

	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	}); err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if got := dispatchedTargets(t, deps); !slices.Equal(got, []string{"example.com"}) {
		t.Errorf("targets = %v, want [example.com] (root, deduplicated)", got)
	}
	if len(inv.queries) != 0 {
		t.Errorf("the inventory was read %d time(s) for subdomain discovery", len(inv.queries))
	}
}

// A pattern in another tool's scanner settings would reach the sensor as
// written: refused.
func TestWildcardTarget_PatternInScannerConfigRefusedForActiveTool(t *testing.T) {
	tenantID := shared.NewID()
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(newFakeSelectorAssets(tenantID))
	deps.toolRepo.addTool("nuclei", true)
	sc := directScan(deps, tenantID, "nuclei", "example.com")
	_ = sc.SetSingleScanner("nuclei", map[string]any{"targets": []any{"*.example.com"}}, 1)
	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	})
	if wildcardCode(err) != scanservice.CodeWildcardTarget {
		t.Fatalf("err = %v, want %s", err, scanservice.CodeWildcardTarget)
	}
}

// One selector adds at most MaxSelectorTargets; the run says so.
func TestWildcardTarget_CapIsRecorded(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	names := make([]string, scanservice.MaxSelectorTargets+5)
	for i := range names {
		names[i] = fmt.Sprintf("h%d.example.com", i)
	}
	inv.byRoot["example.com"] = names
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)
	sc := directScan(deps, tenantID, "nuclei", "*.example.com")
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	}); err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if got := len(dispatchedTargets(t, deps)); got != scanservice.MaxSelectorTargets+1 {
		t.Errorf("dispatched %d, want the cap plus the apex (%d)", got, scanservice.MaxSelectorTargets+1)
	}
	ctx := onlyRun(t, deps)
	exp := ctx[scanservice.RunContextKeyTargetExpansion].([]scanservice.TargetExpansion)
	if !exp[0].Capped || exp[0].Matched != scanservice.MaxSelectorTargets || len(exp[0].Sample) == 0 {
		t.Errorf("expansion = %+v, want capped at %d with a sample", exp[0], scanservice.MaxSelectorTargets)
	}
	warned := false
	for _, w := range ctx["dispatch_warnings"].([]string) {
		warned = warned || strings.Contains(w, "*.example.com")
	}
	if !warned {
		t.Errorf("no warning names the capped selector: %v", ctx["dispatch_warnings"])
	}
}

// An expanded name is gated as the asset it is: an unconfirmed one and one
// outside the actor's data scope are never dispatched.
func TestWildcardTarget_ExpandedNamesGoThroughTheGate(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["example.com"] = []string{"ok.example.com", "review.example.com", "hidden.example.com"}
	gate := &blockAssets{blocked: map[string]attribution.State{inv.id("review.example.com").String(): attribution.StateNeedsReview}}
	act := &refuseAssetIDs{refused: map[shared.ID]bool{inv.id("hidden.example.com"): true}}
	svc, deps := newTestScanService(scanservice.WithAttributionGate(gate), scanservice.WithActScope(act))
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("nuclei", true)
	sc := directScan(deps, tenantID, "nuclei", "*.example.com")
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	}); err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if got := dispatchedTargets(t, deps); !slices.Equal(got, []string{"example.com", "ok.example.com"}) {
		t.Errorf("dispatched %v, want only the apex and the confirmed, in-scope name", got)
	}
	if !act.sawAssets {
		t.Error("the act-scope check was not asked about the expanded assets by id")
	}
}

// The inventory of another tenant is never read: the query carries the
// scan's tenant, and a fake pinned to another tenant adds nothing.
func TestWildcardTarget_OtherTenantsInventoryNeverAdds(t *testing.T) {
	other := newFakeSelectorAssets(shared.NewID())
	other.byRoot["example.com"] = []string{"theirs.example.com"}
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(other)
	deps.toolRepo.addTool("nuclei", true)
	tenantID := shared.NewID()
	sc := directScan(deps, tenantID, "nuclei", "*.example.com")
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	}); err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if got := dispatchedTargets(t, deps); !slices.Equal(got, []string{"example.com"}) {
		t.Errorf("dispatched %v, want the apex only", got)
	}
	if other.queries[0].TenantID != tenantID {
		t.Errorf("query tenant = %s, want the scan's %s", other.queries[0].TenantID, tenantID)
	}
}

// A CIDR is swept by default (handed whole); in inventory mode it becomes
// the addresses the inventory holds inside it.
func TestCIDRTarget_SweepAndInventoryModes(t *testing.T) {
	for _, tc := range []struct {
		mode scan.CIDRMode
		want []string
		read int
	}{
		{"", []string{"203.0.113.0/24"}, 0},
		{scan.CIDRModeSweep, []string{"203.0.113.0/24"}, 0},
		{scan.CIDRModeInventory, []string{"203.0.113.10", "203.0.113.7"}, 1},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			tenantID := shared.NewID()
			inv := newFakeSelectorAssets(tenantID)
			inv.byCIDR["203.0.113.0/24"] = []string{"203.0.113.7", "203.0.113.10"}
			svc, deps := newTestScanService()
			svc.SetSelectorAssets(inv)
			deps.toolRepo.addTool("nuclei", true)
			sc := directScan(deps, tenantID, "nuclei", "203.0.113.0/24")
			sc.TargetOptions = scan.TargetOptions{CIDRMode: tc.mode}
			if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
				TenantID: tenantID.String(), ScanID: sc.ID.String(),
			}); err != nil {
				t.Fatalf("TriggerScan: %v", err)
			}
			if got := dispatchedTargets(t, deps); !slices.Equal(got, tc.want) {
				t.Errorf("dispatched %v, want %v", got, tc.want)
			}
			if len(inv.queries) != tc.read {
				t.Errorf("inventory reads = %d, want %d", len(inv.queries), tc.read)
			}
		})
	}
}

// A workflow: the subdomain discovery step gets the apex, the active step
// the apex and the known names.
func TestWildcardTarget_WorkflowDiscoveryStepGetsTheApex(t *testing.T) {
	tenantID := shared.NewID()
	inv := newFakeSelectorAssets(tenantID)
	inv.byRoot["example.com"] = []string{"api.example.com"}
	svc, deps := newTestScanService()
	svc.SetSelectorAssets(inv)
	deps.toolRepo.addTool("subfinder", true)
	deps.toolRepo.addTool("nuclei", true)
	sc := createTestScanInRepo(deps, tenantID, "Recon chain", scan.ScanTypeWorkflow)
	deps.stepRepo.steps[sc.ScanWorkflowID.String()] = []*scanworkflow.Step{
		{ID: shared.NewID(), ScanWorkflowID: *sc.ScanWorkflowID, StepKey: "find", StepOrder: 1, Tool: "subfinder"},
		{ID: shared.NewID(), ScanWorkflowID: *sc.ScanWorkflowID, StepKey: "probe", StepOrder: 1, Tool: "nuclei"},
	}
	sc.SetTargets([]string{"*.example.com"})
	sc.AssetGroupID = shared.ID{}
	sc.AssetGroupIDs = nil
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	}); err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	byTool := map[string][]string{}
	for _, c := range deps.commandRepo.commands {
		var p map[string]any
		_ = json.Unmarshal(c.Payload, &p)
		tool, _ := p["scanner"].(string)
		ts, _ := p["targets"].([]any)
		for _, v := range ts {
			byTool[tool] = append(byTool[tool], fmt.Sprint(v))
			if strings.HasPrefix(fmt.Sprint(v), "*.") {
				t.Errorf("a pattern reached %s", tool)
			}
		}
	}
	slices.Sort(byTool["nuclei"])
	if !slices.Equal(byTool["subfinder"], []string{"example.com"}) {
		t.Errorf("subfinder targets = %v, want the apex only", byTool["subfinder"])
	}
	if !slices.Equal(byTool["nuclei"], []string{"api.example.com", "example.com"}) {
		t.Errorf("nuclei targets = %v, want the apex and the known name", byTool["nuclei"])
	}
}

// blockAssets refuses the given asset ids as unconfirmed.
type blockAssets struct {
	allOwned
	blocked map[string]attribution.State
}

func (b *blockAssets) ActiveCheckBlocked(_ context.Context, _ shared.ID, ids []string) (map[string]attribution.State, error) {
	out := map[string]attribution.State{}
	for _, id := range ids {
		if st, ok := b.blocked[id]; ok {
			out[id] = st
		}
	}
	return out, nil
}

// refuseAssetIDs is an actor outside whose data scope the given assets are.
type refuseAssetIDs struct {
	refused   map[shared.ID]bool
	sawAssets bool
}

func (r *refuseAssetIDs) Check(_ context.Context, in actscope.Input) (*actscope.Decision, error) {
	d := &actscope.Decision{RefusedTargets: map[string]string{}, RefusedAssets: map[shared.ID]bool{}}
	for _, id := range in.AssetIDs {
		r.sawAssets = true
		if r.refused[id] {
			d.RefusedAssets[id] = true
		}
	}
	return d, nil
}

// Export and import keep the selectors and their options.
func TestTargetOptions_ExportImportRoundTrip(t *testing.T) {
	svc, deps := newTestScanService()
	deps.toolRepo.addTool("nuclei", true)
	tenantID := shared.NewID()
	sc, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
		TenantID: tenantID.String(), Name: "dyn export", ScanType: "single", ScannerName: "nuclei",
		Targets:       []string{"*.example.com", "203.0.113.0/24"},
		TargetOptions: &scan.TargetOptions{CIDRMode: scan.CIDRModeInventory, SeenWithinDays: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := svc.ExportConfig(context.Background(), tenantID, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	doc["name"] = "dyn import"
	data, _ = json.Marshal(doc)
	imported, err := svc.ImportConfig(context.Background(), tenantID, data, shared.NewID().String())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imported.TargetOptions != sc.TargetOptions || !slices.Equal(imported.Targets, sc.Targets) {
		t.Errorf("imported %v %+v, want %v %+v", imported.Targets, imported.TargetOptions, sc.Targets, sc.TargetOptions)
	}
}
