package scan

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app/scope"
	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// stubGroupAssetsRepo overrides only GetGroupAssets; the embedded interface
// panics on any other unexpected call.
type stubGroupAssetsRepo struct {
	assetgroup.Repository
	assets []*assetgroup.GroupAsset
}

func (s *stubGroupAssetsRepo) GetGroupAssets(_ context.Context, _ shared.ID, page pagination.Pagination) (pagination.Result[*assetgroup.GroupAsset], error) {
	return pagination.NewResult(s.assets, int64(len(s.assets)), page), nil
}

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

func TestResolveScanTargets_WarnsForSingleTargetScanner(t *testing.T) {
	svc := &Service{logger: logger.NewNop()}
	got, err := svc.resolveScanTargets(context.Background(), testScan("semgrep", "a", "b", "c"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "2 other target(s)") {
		t.Fatalf("warnings = %v", got.Warnings)
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
