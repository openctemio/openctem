package attribution

import "testing"

// research/531 D6: the provider addresses leave the default populations
// (approved, attributed) and are listed by their own filter; a name in
// dependency (served by a provider) and a person's dependency decision stay.
func TestProviderAddressPopulation(t *testing.T) {
	provider := Record{State: StateDependency, Reason: RuleProviderSharedFrontEnd}
	served := Record{State: StateDependency, Reason: RuleScanDiscovered}
	confirmed := Record{State: StateConfirmed, Reason: RuleMatchesScopeTarget}
	unrecorded := Record{}
	if !IsProviderAddress(provider) || IsProviderAddress(served) || IsProviderAddress(confirmed) {
		t.Fatal("IsProviderAddress misclassifies")
	}
	cases := []struct {
		values []string
		want   map[string]bool
	}{
		{[]string{FilterApproved}, map[string]bool{"provider": false, "served": true, "confirmed": true, "unrecorded": true}},
		{[]string{FilterAttributed}, map[string]bool{"provider": false, "served": true, "confirmed": true, "unrecorded": true}},
		{[]string{FilterProviderAddress}, map[string]bool{"provider": true, "served": false, "confirmed": false, "unrecorded": false}},
		{[]string{FilterApproved, FilterProviderAddress}, map[string]bool{"provider": true, "served": true, "confirmed": true, "unrecorded": true}},
		// An explicit state is what the caller asked for: provider addresses included.
		{[]string{string(StateDependency)}, map[string]bool{"provider": true, "served": true, "confirmed": false, "unrecorded": false}},
	}
	recs := map[string]Record{"provider": provider, "served": served, "confirmed": confirmed, "unrecorded": unrecorded}
	for _, c := range cases {
		f, given, err := ParseFilter(c.values)
		if err != nil || !given {
			t.Fatalf("%v: %v %v", c.values, given, err)
		}
		for k, want := range c.want {
			if got := f.Matches(recs[k]); got != want {
				t.Errorf("%v matches %s = %v, want %v", c.values, k, got, want)
			}
		}
	}
	if got := ProviderAddressSQL("iv"); got != "(iv.state = 'dependency' AND iv.reason = 'provider_shared_front_end')" {
		t.Fatalf("ProviderAddressSQL = %s", got)
	}
}
