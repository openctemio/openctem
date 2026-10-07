package scan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stubGroupAssetsRepo overrides only ListScanMembers; the embedded interface
// panics on any other unexpected call.
type stubGroupAssetsRepo struct {
	assetgroup.Repository
	assets []*assetgroup.GroupAsset
}

func (s *stubGroupAssetsRepo) ListScanMembers(_ context.Context, q assetgroup.ScanMemberQuery) (*assetgroup.ScanMemberPage, error) {
	return scanMemberPage(s.assets, q, 0), nil
}

// scanMemberPage serves members like the repository's ListScanMembers: in the
// given order, archived ones left out and counted on the first page, keyset
// after (AfterName, AfterID), at most limit (or q.Limit when limit is 0).
// Properties of a member come from groupAssetProps.
func scanMemberPage(all []*assetgroup.GroupAsset, q assetgroup.ScanMemberQuery, limit int) *assetgroup.ScanMemberPage {
	if limit == 0 || (q.Limit > 0 && q.Limit < limit) {
		limit = q.Limit
	}
	page := &assetgroup.ScanMemberPage{}
	first := q.AfterID.IsZero()
	started := first
	for _, a := range all {
		if a.Status == "archived" {
			if first {
				page.ArchivedCount++
			}
			continue
		}
		if !started {
			started = a.ID == q.AfterID
			continue
		}
		if limit > 0 && len(page.Members) == limit {
			continue
		}
		page.Members = append(page.Members, &assetgroup.ScanMember{
			ID: a.ID, Name: a.Name, Type: a.Type, Status: a.Status, Properties: groupAssetProps[a.ID],
		})
	}
	return page
}

// groupAssetProps holds test members' properties by asset id.
var groupAssetProps = map[shared.ID]map[string]any{}

// stubExclusions excludes candidates by value.
type stubExclusions struct {
	values map[string]bool
	err    error
}

func (s *stubExclusions) ExcludedTargets(_ context.Context, _ string, cs []scope.ExclusionCandidate) (map[shared.ID]bool, error) {
	if s.err != nil {
		return nil, s.err
	}
	out := map[shared.ID]bool{}
	for _, c := range cs {
		for _, v := range c.Values {
			if s.values[v] {
				out[c.ID] = true
			}
		}
	}
	return out, nil
}

func testScan(scanner string, targets ...string) *scan.Scan {
	return &scan.Scan{ID: shared.NewID(), TenantID: shared.NewID(), Name: "t", ScannerName: scanner, Targets: targets}
}

func TestResolveScanTargets_GroupMembersAndDirectTargets(t *testing.T) {
	svc := &Service{
		assetGroupRepo: &stubGroupAssetsRepo{assets: []*assetgroup.GroupAsset{
			{ID: shared.NewID(), Name: "10.0.0.5"},
			{ID: shared.NewID(), Name: "app.example.com"},
		}},
		logger: logger.NewNop(),
	}
	sc := testScan("nuclei", "app.example.com", " 203.0.113.9 ")
	sc.AssetGroupID = shared.NewID()

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"app.example.com", "203.0.113.9", "10.0.0.5"} // deduped, direct first
	if !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("targets = %v, want %v", got.Targets, want)
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("nuclei takes a list, no warning expected: %v", got.Warnings)
	}
}

// Exclusions are enforced server-side for direct targets and group members.
func TestResolveScanTargets_RemovesExcluded(t *testing.T) {
	svc := &Service{
		assetGroupRepo: &stubGroupAssetsRepo{assets: []*assetgroup.GroupAsset{
			{ID: shared.NewID(), Name: "prod-db.internal.example.com"},
		}},
		scopeExclusions: &stubExclusions{values: map[string]bool{"prod-db.internal.example.com": true, "203.0.113.9": true}},
		logger:          logger.NewNop(),
	}
	sc := testScan("nuclei", "203.0.113.9", "app.example.com")
	sc.AssetGroupID = shared.NewID()

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Targets, []string{"app.example.com"}) || got.Excluded != 2 {
		t.Fatalf("targets=%v excluded=%d", got.Targets, got.Excluded)
	}
}

// A failed exclusion lookup must stop the dispatch, never scan everything.
func TestResolveScanTargets_ExclusionErrorFailsClosed(t *testing.T) {
	svc := &Service{
		scopeExclusions: &stubExclusions{err: errors.New("db down")},
		logger:          logger.NewNop(),
	}
	if _, err := svc.resolveScanTargets(context.Background(), testScan("nuclei", "app.example.com")); err == nil {
		t.Fatal("exclusion lookup failure must fail the dispatch")
	}
}

func TestRecordResolvedTargets_AllExcludedRefused(t *testing.T) {
	ctx := map[string]any{}
	err := recordResolvedTargets(testScan("nuclei"), &resolvedTargets{Excluded: 3}, ctx)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("got %v, want validation error", err)
	}
	if ctx["excluded_target_count"] != 3 {
		t.Fatalf("context not recorded: %v", ctx)
	}
}

// A single-target scanner now gets one command per target (perTargetPlan),
// so the old "only the first target is scanned" warning is gone; the per-run
// job cap is enforced here instead.
func TestResolveScanTargets_SingleTargetScanner(t *testing.T) {
	svc := &Service{logger: logger.NewNop()}
	got, err := svc.resolveScanTargets(context.Background(), testScan("semgrep", "a", "b", "c"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", got.Warnings)
	}

	many := make([]string, maxZoneJobsPerRun+1)
	for i := range many {
		many[i] = fmt.Sprintf("repo-%d", i)
	}
	if _, err := svc.resolveScanTargets(context.Background(), testScan("semgrep", many...)); err == nil ||
		!strings.Contains(err.Error(), "one target per job") {
		t.Fatalf("err = %v, want the per-run job cap", err)
	}
	// A list scanner is not bound by the job cap.
	if _, err := svc.resolveScanTargets(context.Background(), testScan("nuclei", many...)); err != nil {
		t.Fatalf("nuclei with %d targets: %v", len(many), err)
	}
}

// Before this change only Targets[0] was ever dispatched. nuclei prefers
// `target` over `targets`, so `target` must be absent for a list.
func TestApplyTargetsToPayload(t *testing.T) {
	for name, tc := range map[string]struct {
		scanner    string
		targets    []string
		wantTarget any
	}{
		"nuclei, many targets: full list, no single target": {"nuclei", []string{"a", "b"}, nil},
		"nuclei, one target: both fields":                   {"nuclei", []string{"a"}, "a"},
		"single-target scanner keeps v1 shape":              {"semgrep", []string{"a", "b"}, "a"},
		"tenable, many targets":                             {"tenable", []string{"a", "b"}, nil},
	} {
		p := map[string]any{}
		applyTargetsToPayload(p, tc.scanner, tc.targets)
		if !reflect.DeepEqual(p["targets"], tc.targets) {
			t.Errorf("%s: targets = %v", name, p["targets"])
		}
		if p["target"] != tc.wantTarget {
			t.Errorf("%s: target = %v, want %v", name, p["target"], tc.wantTarget)
		}
	}
	p := map[string]any{}
	applyTargetsToPayload(p, "nuclei", nil)
	if len(p) != 0 {
		t.Errorf("no targets must leave the payload untouched: %v", p)
	}
}

func TestIsInternalTarget(t *testing.T) {
	for target, want := range map[string]bool{
		"10.1.2.3": true, "192.168.0.0/16": true, "172.16.5.4:8443": true,
		"http://10.230.43.33:8834/": true, "127.0.0.1": true, "[::1]": true,
		"fd00::1": true, "169.254.169.254": true, "100.64.1.1": true,
		"localhost": true, "db.internal": true, "printer.local": true,
		"203.0.113.9": false, "example.com": false, "https://app.example.com/login": false,
		"8.8.8.0/24": false,
	} {
		if got := isInternalTarget(target); got != want {
			t.Errorf("isInternalTarget(%q) = %v, want %v", target, got, want)
		}
	}
}

type stubSelector struct {
	tenantSensor bool
	canUse       bool
}

func (s stubSelector) CheckSensorAvailability(context.Context, shared.ID, string, bool) *SensorAvailability {
	return &SensorAvailability{}
}
func (s stubSelector) CanUsePlatformSensors(context.Context, shared.ID) (bool, string) {
	return s.canUse, "not enabled"
}
func (s stubSelector) SelectSensor(context.Context, SelectSensorRequest) (*SelectSensorResult, error) {
	if s.tenantSensor {
		return &SelectSensorResult{Sensor: &sensor.Sensor{}}, nil
	}
	return &SelectSensorResult{}, nil
}

// No silent fallback to shared sensors, and never for internal targets.
func TestShouldUsePlatformSensor(t *testing.T) {
	ctx := context.Background()
	public := []string{"app.example.com"}
	internal := []string{"10.0.0.5"}

	cases := []struct {
		name    string
		sel     stubSelector
		pref    scan.SensorPreference
		group   bool
		targets []string
		want    bool
		wantErr bool
	}{
		{"auto, tenant sensor busy, platform not allowed: wait for tenant", stubSelector{false, false}, scan.SensorPreferenceAuto, false, public, false, false},
		{"auto, tenant sensor busy, platform allowed, public: platform", stubSelector{false, true}, scan.SensorPreferenceAuto, false, public, true, false},
		{"auto, internal target never goes to platform", stubSelector{false, true}, scan.SensorPreferenceAuto, false, internal, false, false},
		{"auto, asset group never goes to platform", stubSelector{false, true}, scan.SensorPreferenceAuto, true, public, false, false},
		{"auto, tenant sensor available: tenant", stubSelector{true, true}, scan.SensorPreferenceAuto, false, public, false, false},
		{"explicit platform with internal target: refused", stubSelector{false, true}, scan.SensorPreferencePlatform, false, internal, false, true},
		{"explicit platform, not allowed: refused", stubSelector{false, false}, scan.SensorPreferencePlatform, false, public, false, true},
		{"explicit platform, allowed, public: platform", stubSelector{false, true}, scan.SensorPreferencePlatform, false, public, true, false},
	}
	for _, tc := range cases {
		svc := &Service{sensorSelector: tc.sel, logger: logger.NewNop()}
		sc := testScan("nuclei")
		sc.SensorPreference = tc.pref
		if tc.group {
			sc.AssetGroupID = shared.NewID()
		}
		got, err := svc.shouldUsePlatformSensor(ctx, sc, tc.targets)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("%s: got %v, err %v", tc.name, got, err)
		}
	}
}

// stubGroupsRepo serves members per group id.
type stubGroupsRepo struct {
	assetgroup.Repository
	byGroup map[shared.ID][]*assetgroup.GroupAsset
	calls   map[shared.ID]int
}

func (s *stubGroupsRepo) ListScanMembers(_ context.Context, q assetgroup.ScanMemberQuery) (*assetgroup.ScanMemberPage, error) {
	if s.calls == nil {
		s.calls = map[shared.ID]int{}
	}
	if q.AfterID.IsZero() {
		s.calls[q.GroupID]++
	}
	return scanMemberPage(s.byGroup[q.GroupID], q, 0), nil
}

func groupAsset(name string) *assetgroup.GroupAsset {
	return &assetgroup.GroupAsset{ID: shared.NewID(), Name: name}
}

// Every asset group of a scan is resolved, not only the first: members are
// merged and deduplicated, exclusions apply to all of them, and an empty
// group is reported.
func TestResolveScanTargets_AllAssetGroups(t *testing.T) {
	g1, g2, g3 := shared.NewID(), shared.NewID(), shared.NewID()
	shared1 := groupAsset("shared.example.com")
	repo := &stubGroupsRepo{byGroup: map[shared.ID][]*assetgroup.GroupAsset{
		g1: {groupAsset("a.example.com"), shared1},
		g2: {groupAsset("b.example.com"), {ID: shared1.ID, Name: shared1.Name}, groupAsset("excluded.example.com")},
		g3: {},
	}}
	svc := &Service{
		assetGroupRepo:  repo,
		scopeExclusions: &stubExclusions{values: map[string]bool{"excluded.example.com": true}},
		logger:          logger.NewNop(),
	}
	sc := testScan("nuclei")
	sc.SetAssetGroupIDs([]shared.ID{g1, g2, g3, g2})

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "shared.example.com", "b.example.com"}
	if !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("targets = %v, want %v", got.Targets, want)
	}
	if got.Excluded != 1 {
		t.Fatalf("excluded = %d, want 1", got.Excluded)
	}
	for _, g := range []shared.ID{g1, g2, g3} {
		if repo.calls[g] != 1 {
			t.Fatalf("group %s listed %d times, want once", g, repo.calls[g])
		}
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], g3.String()) || !strings.Contains(got.Warnings[0], "no assets") {
		t.Fatalf("want one warning naming the empty group, got %v", got.Warnings)
	}
}

// The per-run cap counts the targets of every group together.
func TestResolveScanTargets_CapAcrossGroups(t *testing.T) {
	g1, g2 := shared.NewID(), shared.NewID()
	mk := func(prefix string, n int) []*assetgroup.GroupAsset {
		out := make([]*assetgroup.GroupAsset, n)
		for i := range out {
			out[i] = groupAsset(prefix + "-" + shared.NewID().String() + ".example.com")
		}
		return out
	}
	half := maxResolvedTargets/2 + 1
	svc := &Service{
		assetGroupRepo: &stubGroupsRepo{byGroup: map[shared.ID][]*assetgroup.GroupAsset{g1: mk("a", half), g2: mk("b", half)}},
		logger:         logger.NewNop(),
	}
	sc := testScan("nuclei")
	sc.SetAssetGroupIDs([]shared.ID{g1, g2})
	if _, err := svc.resolveScanTargets(context.Background(), sc); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want the target cap to apply across groups, got %v", err)
	}
}

// A scan that resolves to nothing (an empty group, no direct targets) must not
// dispatch a command with no targets.
func TestRecordResolvedTargets_NoTargetsRefused(t *testing.T) {
	ctx := map[string]any{}
	err := recordResolvedTargets(testScan("nuclei"), &resolvedTargets{}, ctx)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("got %v, want validation error", err)
	}
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "NO_TARGETS" {
		t.Fatalf("want domain error NO_TARGETS, got %#v", err)
	}
}

// sensor_preference=platform must never silently become a tenant job: the
// trigger is refused before any run or command exists.
func TestDecideSensorRouting(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		sel      SensorSelector
		pref     scan.SensorPreference
		group    bool
		targets  []string
		want     string
		wantErr  bool
		wantWarn bool
	}{
		{"platform + asset group refused", stubSelector{false, true}, scan.SensorPreferencePlatform, true, []string{"a.example.com"}, "", true, false},
		{"platform + internal target refused", stubSelector{false, true}, scan.SensorPreferencePlatform, false, []string{"10.0.0.5"}, "", true, false},
		{"platform not allowed refused", stubSelector{false, false}, scan.SensorPreferencePlatform, false, []string{"a.example.com"}, "", true, false},
		{"platform public allowed", stubSelector{false, true}, scan.SensorPreferencePlatform, false, []string{"a.example.com"}, sensorRoutingPlatform, false, false},
		{"auto selector error: tenant, recorded", errSelector{}, scan.SensorPreferenceAuto, false, []string{"a.example.com"}, sensorRoutingTenant, false, true},
		{"tenant", stubSelector{false, true}, scan.SensorPreferenceTenant, false, []string{"a.example.com"}, sensorRoutingTenant, false, false},
	}
	for _, tc := range cases {
		svc := &Service{sensorSelector: tc.sel, logger: logger.NewNop()}
		sc := testScan("nuclei")
		sc.SensorPreference = tc.pref
		if tc.group {
			sc.SetAssetGroupIDs([]shared.ID{shared.NewID()})
		}
		got, err := svc.decideSensorRouting(ctx, sc, tc.targets, nil)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
		if err != nil {
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: refusal must be a validation error, got %v", tc.name, err)
			}
			continue
		}
		if got.Routing != tc.want || (got.Warning != "") != tc.wantWarn {
			t.Fatalf("%s: got %+v", tc.name, got)
		}
	}
}

// Only the multi-group field set (no legacy AssetGroupID) still counts as an
// asset group for platform routing.
func TestShouldUsePlatformSensor_AssetGroupIDsOnly(t *testing.T) {
	svc := &Service{sensorSelector: stubSelector{false, true}, logger: logger.NewNop()}
	sc := testScan("nuclei")
	sc.AssetGroupIDs = []shared.ID{shared.NewID()}
	got, err := svc.shouldUsePlatformSensor(context.Background(), sc, []string{"a.example.com"})
	if err != nil || got {
		t.Fatalf("asset groups must never go to platform sensors: got %v, %v", got, err)
	}
}

type errSelector struct{ stubSelector }

func (errSelector) SelectSensor(context.Context, SelectSensorRequest) (*SelectSensorResult, error) {
	return nil, errors.New("selector down")
}

// pagedGroupAssetsRepo pages like a repository that returns fewer rows than
// asked for (100 per page), so the keyset loop must keep reading.
type pagedGroupAssetsRepo struct {
	assetgroup.Repository
	assets []*assetgroup.GroupAsset
}

func (s *pagedGroupAssetsRepo) ListScanMembers(_ context.Context, q assetgroup.ScanMemberQuery) (*assetgroup.ScanMemberPage, error) {
	return scanMemberPage(s.assets, q, 100), nil
}

// A scan of a 250-asset group scans all 250. The member listing asked for
// pages of 500, pagination clamps to 100, and the page arithmetic then
// stopped after the first page: only 100 members were ever scanned.
func TestResolveScanTargets_GroupLargerThanOnePage(t *testing.T) {
	members := make([]*assetgroup.GroupAsset, 250)
	for i := range members {
		members[i] = &assetgroup.GroupAsset{ID: shared.NewID(), Name: fmt.Sprintf("h%03d.example.com", i)}
	}
	svc := &Service{assetGroupRepo: &pagedGroupAssetsRepo{assets: members}, logger: logger.NewNop()}
	sc := testScan("nuclei")
	sc.AssetGroupID = shared.NewID()

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 250 {
		t.Fatalf("resolved %d of 250 group members", len(got.Targets))
	}
}

// stubGate blocks the given asset ids and typed targets.
type stubGate struct {
	blocked      map[string]attribution.State
	blockedTyped map[string]attribution.State
	// ceiling is the max_tier of the entry covering a target (absent: at
	// least every tier).
	ceiling    map[string]scopedom.Tier
	err        error
	asked      []string
	askedTyped []string
}

func (g *stubGate) BlockedTargets(_ context.Context, _ shared.ID, targets []string) (map[string]attribution.State, error) {
	g.askedTyped = append(g.askedTyped, targets...)
	if g.err != nil {
		return nil, g.err
	}
	out := map[string]attribution.State{}
	for _, t := range targets {
		if s, ok := g.blockedTyped[t]; ok {
			out[t] = s
		}
	}
	return out, nil
}

func (g *stubGate) TierExceeded(_ context.Context, _ shared.ID, targets []string, tier scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	if g.err != nil {
		return nil, g.err
	}
	out := map[string]*scopedom.RuleRef{}
	for _, t := range targets {
		if c, ok := g.ceiling[t]; ok && c < tier {
			out[t] = &scopedom.RuleRef{Kind: scopedom.RuleScopeTarget, ID: "entry-" + t, Pattern: t}
		}
	}
	return out, nil
}

func (g *stubGate) ActiveCheckBlocked(_ context.Context, _ shared.ID, ids []string) (map[string]attribution.State, error) {
	g.asked = append(g.asked, ids...)
	if g.err != nil {
		return nil, g.err
	}
	out := map[string]attribution.State{}
	for _, id := range ids {
		if s, ok := g.blocked[id]; ok {
			out[id] = s
		}
	}
	return out, nil
}

// RFC-036 §6.3 / O4: a group member whose ownership is not confirmed (for
// example a name found only in CT under an unverified domain) is never
// scanned; a direct target the tenant typed is its own assertion and is.
func TestResolveScanTargets_SkipsUnconfirmedGroupMembers(t *testing.T) {
	confirmed := &assetgroup.GroupAsset{ID: shared.NewID(), Name: "www.proven.com"}
	review := &assetgroup.GroupAsset{ID: shared.NewID(), Name: "www.listed.com"}
	typed := &assetgroup.GroupAsset{ID: shared.NewID(), Name: "api.listed.com"}
	gate := &stubGate{blocked: map[string]attribution.State{
		review.ID.String(): attribution.StateNeedsReview,
		typed.ID.String():  attribution.StateNeedsReview,
	}}
	svc := &Service{
		assetGroupRepo:  &stubGroupAssetsRepo{assets: []*assetgroup.GroupAsset{confirmed, review, typed}},
		attributionGate: gate,
		logger:          logger.NewNop(),
	}
	sc := testScan("nuclei", "api.listed.com")
	sc.AssetGroupID = shared.NewID()

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Targets, []string{"api.listed.com", "www.proven.com"}) || got.Unconfirmed != 1 {
		t.Fatalf("targets=%v unconfirmed=%d", got.Targets, got.Unconfirmed)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings = %v", got.Warnings)
	}

	// Only unconfirmed members: refused, nothing dispatched.
	svc.assetGroupRepo = &stubGroupAssetsRepo{assets: []*assetgroup.GroupAsset{review}}
	only := testScan("nuclei")
	only.AssetGroupID = shared.NewID()
	r, err := svc.resolveScanTargets(context.Background(), only)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordResolvedTargets(only, r, map[string]any{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("all-unconfirmed run not refused: %v", err)
	}

	// The gate failing stops the dispatch (fail closed).
	svc.attributionGate = &stubGate{err: errors.New("db down")}
	if _, err := svc.resolveScanTargets(context.Background(), only); err == nil {
		t.Fatal("attribution lookup failure must fail the dispatch")
	}
}

// A group member is an asset: archived members are not scanned, and an
// exclusion of an address the member resolves to excludes it, also when the
// member's name was already given as a direct target.
func TestResolveScanTargets_GroupMemberAddressesAndArchived(t *testing.T) {
	web := &assetgroup.GroupAsset{ID: shared.NewID(), Name: "web.example.com", Type: "domain", Status: "active"}
	db := &assetgroup.GroupAsset{ID: shared.NewID(), Name: "db.example.com", Type: "domain", Status: "active"}
	app := &assetgroup.GroupAsset{ID: shared.NewID(), Name: "app.example.com", Type: "domain", Status: "stale"}
	old := &assetgroup.GroupAsset{ID: shared.NewID(), Name: "old.example.com", Type: "domain", Status: "archived"}
	groupAssetProps[web.ID] = map[string]any{"ip_addresses": []any{"10.9.9.10"}}
	groupAssetProps[db.ID] = map[string]any{"ip": "10.9.9.11"}
	t.Cleanup(func() { delete(groupAssetProps, web.ID); delete(groupAssetProps, db.ID) })

	svc := &Service{
		assetGroupRepo:  &stubGroupAssetsRepo{assets: []*assetgroup.GroupAsset{web, db, app, old}},
		scopeExclusions: &stubExclusions{values: map[string]bool{"10.9.9.10": true, "10.9.9.11": true}},
		logger:          logger.NewNop(),
	}
	sc := testScan("nuclei", "web.example.com")
	sc.AssetGroupID = shared.NewID()

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Targets, []string{"app.example.com"}) {
		t.Fatalf("targets = %v, want only app.example.com", got.Targets)
	}
	if !reflect.DeepEqual(got.ExcludedNames, []string{"web.example.com", "db.example.com"}) {
		t.Fatalf("excluded = %v, want web and db (excluded by address)", got.ExcludedNames)
	}
	if got.Archived != 1 {
		t.Fatalf("archived = %d, want 1", got.Archived)
	}
	found := false
	for _, w := range got.Warnings {
		found = found || strings.Contains(w, "1 archived asset")
	}
	if !found {
		t.Fatalf("want a warning about the skipped archived asset, got %v", got.Warnings)
	}
}
