package scan

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// listZones is a ZoneDirectory with fixed zones.
type listZones struct{ zones []*scanzone.Zone }

func (l listZones) List(context.Context, shared.ID) ([]*scanzone.Zone, error) { return l.zones, nil }
func (l listZones) RoutableSensors(context.Context, shared.ID, []shared.ID, string) (map[shared.ID][]scanzone.SensorCandidate, error) {
	return nil, nil
}

func mustGateZone(t *testing.T, tenant shared.ID, name string, sensors []shared.ID, ranges ...string) *scanzone.Zone {
	t.Helper()
	z, err := scanzone.NewZone(tenant, name, "", false, ranges, nil)
	if err != nil {
		t.Fatal(err)
	}
	z.SensorIDs = sensors
	return z
}

func refusedTargets(d *DispatchTargets) []string {
	out := make([]string, 0, len(d.Refused))
	for _, r := range d.Refused {
		out = append(out, r.Target)
	}
	return out
}

func TestResolveDispatchTargets_NoZones(t *testing.T) {
	svc := &Service{scopeExclusions: &stubExclusions{values: map[string]bool{"excluded.example.com": true}}, attributionGate: &stubGate{}, logger: logger.NewNop()}
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: shared.NewID(),
		Targets: []string{
			"app.example.com", " APP.example.com ", "excluded.example.com",
			"10.0.0.5", "127.0.0.1", "169.254.169.254", "203.0.113.9",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"app.example.com", "203.0.113.9"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
	if want := []string{"excluded.example.com"}; !reflect.DeepEqual(got.Excluded, want) {
		t.Fatalf("excluded = %v, want %v", got.Excluded, want)
	}
	refused := strings.Join(refusedTargets(got), ",")
	for _, ip := range []string{"10.0.0.5", "127.0.0.1", "169.254.169.254"} {
		if !strings.Contains(refused, ip) {
			t.Fatalf("%s must be refused without a zone covering it; refused = %v", ip, refused)
		}
	}
	if z, err := got.SingleZone(); err != nil || z != nil {
		t.Fatalf("SingleZone = %v, %v; want unzoned", z, err)
	}
}

func TestResolveDispatchTargets_FailsClosed(t *testing.T) {
	in := DispatchTargetsInput{TenantID: shared.NewID(), Targets: []string{"app.example.com"}}

	if _, err := (&Service{logger: logger.NewNop()}).ResolveDispatchTargets(context.Background(), in); !errors.Is(err, ErrDispatchGateUnavailable) {
		t.Fatalf("no exclusion filter: err = %v, want ErrDispatchGateUnavailable", err)
	}
	svc := &Service{scopeExclusions: &stubExclusions{err: errors.New("db down")}, logger: logger.NewNop()}
	if got, err := svc.ResolveDispatchTargets(context.Background(), in); err == nil {
		t.Fatalf("a failed exclusion lookup must refuse the dispatch, got %+v", got)
	}
}

func TestResolveDispatchTargets_Zones(t *testing.T) {
	tenant := shared.NewID()
	inZone, other := shared.NewID(), shared.NewID()
	dcA := mustGateZone(t, tenant, "dc-a", []shared.ID{inZone}, "10.1.0.0/16")
	dcB := mustGateZone(t, tenant, "dc-b", []shared.ID{other}, "10.2.0.0/16")
	empty := mustGateZone(t, tenant, "lab", nil, "10.3.0.0/16")
	svc := &Service{
		scopeExclusions: &stubExclusions{values: map[string]bool{"10.1.0.9": true}},
		zones:           listZones{zones: []*scanzone.Zone{dcA, dcB, empty}},
		attributionGate: &stubGate{},
		logger:          logger.NewNop(),
	}

	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: tenant,
		SensorID: &inZone,
		Targets:  []string{"10.1.0.5", "10.1.0.9", "10.2.0.5", "10.3.0.5", "10.4.0.5", "203.0.113.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.1.0.5", "203.0.113.9"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
	if want := []string{"10.1.0.9"}; !reflect.DeepEqual(got.Excluded, want) {
		t.Fatalf("excluded = %v, want %v", got.Excluded, want)
	}
	// 10.2.0.5: the pinned sensor is not in dc-b; 10.3.0.5: lab has no
	// sensor; 10.4.0.5: private, outside every zone.
	if want := []string{"10.4.0.5", "10.2.0.5", "10.3.0.5"}; !sameSet(refusedTargets(got), want) {
		t.Fatalf("refused = %v, want %v", got.Refused, want)
	}
	if z := got.Zone("10.1.0.5"); z == nil || !z.ID.Equals(dcA.ID) {
		t.Fatalf("zone of 10.1.0.5 = %v, want dc-a", z)
	}
	if _, err := got.SingleZone(); err == nil {
		t.Fatal("a zoned and an unzoned target in one job must need a split")
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// A target that names an inventory asset is refused while the asset is not
// confirmed (RFC-036 O4), and an exclusion of the asset name excludes a URL
// on it. A target with no asset (typed by the tenant, O8) is not checked.
func TestResolveDispatchTargets_Assets(t *testing.T) {
	confirmed, review, shared2 := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	gate := &stubGate{blocked: map[string]attribution.State{review: attribution.StateNeedsReview, shared2: attribution.StateRejected}}
	svc := &Service{
		scopeExclusions: &stubExclusions{values: map[string]bool{"legacy.example.com": true}},
		attributionGate: gate,
		logger:          logger.NewNop(),
	}
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: shared.NewID(),
		Targets:  []string{"ok.example.com", "review.example.com", "https://legacy.example.com/a", "typed.example.com", "both.example.com"},
		Assets: map[string]DispatchAsset{
			"OK.example.com":               {IDs: []string{confirmed}},
			"review.example.com":           {IDs: []string{review}},
			"https://legacy.example.com/a": {IDs: []string{confirmed}, AlsoMatch: []string{"legacy.example.com"}},
			// Two assets share an address: one unconfirmed refuses it.
			"both.example.com": {IDs: []string{confirmed, shared2}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ok.example.com", "typed.example.com"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
	if want := []string{"https://legacy.example.com/a"}; !reflect.DeepEqual(got.Excluded, want) {
		t.Fatalf("excluded = %v, want %v", got.Excluded, want)
	}
	if want := []string{"review.example.com", "both.example.com"}; !sameSet(refusedTargets(got), want) {
		t.Fatalf("refused = %v, want %v", got.Refused, want)
	}
	for _, r := range got.Refused {
		if !strings.Contains(r.Reason, "ownership is not confirmed") {
			t.Fatalf("reason = %q", r.Reason)
		}
	}
	// The excluded asset is not looked up.
	for _, id := range gate.asked {
		if id == "" {
			t.Fatal("empty asset id asked")
		}
	}
}

func TestResolveDispatchTargets_AssetsFailClosed(t *testing.T) {
	in := DispatchTargetsInput{TenantID: shared.NewID(), Targets: []string{"app.example.com"},
		Assets: map[string]DispatchAsset{"app.example.com": {IDs: []string{shared.NewID().String()}}}}
	excl := &stubExclusions{}

	if _, err := (&Service{scopeExclusions: excl, logger: logger.NewNop()}).ResolveDispatchTargets(context.Background(), in); !errors.Is(err, ErrAttributionGateUnavailable) {
		t.Fatalf("no attribution gate: err = %v, want ErrAttributionGateUnavailable", err)
	}
	svc := &Service{scopeExclusions: excl, attributionGate: &stubGate{err: errors.New("db down")}, logger: logger.NewNop()}
	if got, err := svc.ResolveDispatchTargets(context.Background(), in); err == nil {
		t.Fatalf("a failed attribution lookup must refuse the dispatch, got %+v", got)
	}
	in.Assets = map[string]DispatchAsset{"app.example.com": {}}
	if _, err := (&Service{scopeExclusions: excl, attributionGate: &stubGate{}, logger: logger.NewNop()}).ResolveDispatchTargets(context.Background(), in); err == nil {
		t.Fatal("an asset entry without an id must refuse the dispatch")
	}
	// A typed target is checked too (it may name an asset or sit under a
	// rejected name): no gate refuses it, a gate allows it.
	typed := DispatchTargetsInput{TenantID: in.TenantID, Targets: in.Targets}
	if _, err := (&Service{scopeExclusions: excl, logger: logger.NewNop()}).ResolveDispatchTargets(context.Background(), typed); !errors.Is(err, ErrAttributionGateUnavailable) {
		t.Fatalf("typed target, no gate: err = %v, want ErrAttributionGateUnavailable", err)
	}
	if _, err := (&Service{scopeExclusions: excl, attributionGate: &stubGate{err: errors.New("db down")}, logger: logger.NewNop()}).ResolveDispatchTargets(context.Background(), typed); err == nil {
		t.Fatal("typed target: a failed ownership lookup must refuse the dispatch")
	}
	if _, err := (&Service{scopeExclusions: excl, attributionGate: &stubGate{}, logger: logger.NewNop()}).ResolveDispatchTargets(context.Background(), typed); err != nil {
		t.Fatalf("typed target: %v", err)
	}
}
