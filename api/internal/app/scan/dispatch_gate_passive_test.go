package scan

import (
	"context"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// research/27 §5.7: a passive (T0) stage of a chain may resolve a name that
// nobody confirmed yet, but never a rejected one; every other path keeps the
// full active-scan gate. Exclusions and the target validator apply to both.
func TestResolveDispatchTargets_PassiveOnly(t *testing.T) {
	review, rejected, unattributed := shared.NewID(), shared.NewID(), shared.NewID()
	gate := &stubGate{blocked: map[string]attribution.State{
		review.String():       attribution.StateNeedsReview,
		rejected.String():     attribution.StateRejected,
		unattributed.String(): attribution.StateUnattributed,
	}, blockedTyped: map[string]attribution.State{
		"old.example.com": attribution.StateRejected, // a tombstoned name, typed
	}}
	svc := &Service{scopeExclusions: &stubExclusions{values: map[string]bool{"excluded.example.com": true}},
		attributionGate: gate, logger: logger.NewNop()}
	in := DispatchTargetsInput{
		TenantID: shared.NewID(),
		Targets:  []string{"new.example.com", "gone.example.com", "cdn.example.com", "old.example.com", "excluded.example.com", "169.254.169.254"},
		Assets: map[string]DispatchAsset{
			"new.example.com":  {IDs: []string{review.String()}},
			"gone.example.com": {IDs: []string{rejected.String()}},
			"cdn.example.com":  {IDs: []string{unattributed.String()}},
		},
	}

	active, err := svc.ResolveDispatchTargets(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Allowed) != 0 {
		t.Fatalf("active gate allowed %v; a name nobody confirmed must not be actively probed", active.Allowed)
	}

	in.PassiveOnly = true
	passive, err := svc.ResolveDispatchTargets(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"new.example.com", "cdn.example.com"}; !reflect.DeepEqual(passive.Allowed, want) {
		t.Fatalf("passive allowed = %v, want %v (needs_review and unattributed may be resolved)", passive.Allowed, want)
	}
	if want := []string{"excluded.example.com"}; !reflect.DeepEqual(passive.Excluded, want) {
		t.Fatalf("passive excluded = %v", passive.Excluded)
	}
	refused := map[string]string{}
	for _, r := range passive.Refused {
		refused[r.Target] = r.Reason
	}
	for _, name := range []string{"gone.example.com", "old.example.com"} {
		if refused[name] != ReasonOwnershipNotConfirmed {
			t.Errorf("%s: a rejected name reached a passive stage (refused = %v)", name, refused)
		}
	}
	if _, ok := refused["169.254.169.254"]; !ok {
		t.Error("the metadata address passed the target validator")
	}
}

// Two assets behind one target: a rejection of either refuses it at T0.
func TestResolveDispatchTargets_PassiveOnlyAnyRejectedAssetRefuses(t *testing.T) {
	review, rejected := shared.NewID(), shared.NewID()
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{blocked: map[string]attribution.State{
		review.String(): attribution.StateNeedsReview, rejected.String(): attribution.StateRejected,
	}}, logger: logger.NewNop()}
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: shared.NewID(), Targets: []string{"shared.example.com"}, PassiveOnly: true,
		Assets: map[string]DispatchAsset{"shared.example.com": {IDs: []string{review.String(), rejected.String()}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 {
		t.Fatalf("allowed %v", got.Allowed)
	}
}
