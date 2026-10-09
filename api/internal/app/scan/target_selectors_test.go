package scan

import (
	"slices"
	"testing"
)

func TestDropUnderRoots(t *testing.T) {
	targets := []string{"example.com", "api.example.com", "https://www.example.com/x", "notexample.com", "other.net", "a.b.example.com:8443"}
	got := dropUnderRoots(targets, []string{"example.com"})
	if want := []string{"example.com", "notexample.com", "other.net"}; !slices.Equal(got, want) {
		t.Errorf("dropUnderRoots = %v, want %v", got, want)
	}
	if got := dropUnderRoots(targets, nil); !slices.Equal(got, targets) {
		t.Errorf("no roots changed the list: %v", got)
	}
}

func TestDiscoverySeeds(t *testing.T) {
	rc := map[string]any{"targets": []any{"example.com", "api.example.com"}, RunContextKeySelectorRoots: []any{"example.com"}}
	if got := DiscoverySeeds("subfinder", nil, rc); got == nil || !slices.Equal(got.Targets, []string{"example.com"}) {
		t.Errorf("subfinder seeds = %+v, want the apex", got)
	}
	seeds := &StepTargets{Targets: []string{"example.com", "api.example.com"}, Refused: 2, Reason: "r"}
	got := DiscoverySeeds("subfinder", seeds, rc)
	if !slices.Equal(got.Targets, []string{"example.com"}) || got.Refused != 2 || got.Reason != "r" {
		t.Errorf("subfinder with filtered seeds = %+v", got)
	}
	if seeds.Targets[1] != "api.example.com" {
		t.Error("the caller's seeds were changed in place")
	}
	if got := DiscoverySeeds("nuclei", seeds, rc); got != seeds {
		t.Errorf("nuclei seeds changed: %+v", got)
	}
	if got := DiscoverySeeds("subfinder", seeds, map[string]any{}); got != seeds {
		t.Errorf("no selector roots changed the seeds: %+v", got)
	}
}

func TestValidateSelectorTargets(t *testing.T) {
	for target, ok := range map[string]bool{
		"*.example.com":    true,
		"*.Example.co.uk":  true,
		"example.com":      true, // not a selector
		"203.0.113.0/24":   true, // a CIDR is checked by the target validator
		"*.com":            false,
		"*.co.uk":          false,
		"*.amazonaws.com":  false,
		"*.*.example.com":  false,
		"*.ex ample.com":   false,
		"*.":               false,
		"*.example.gov.vn": false,
		"*.agency.gov":     false,
	} {
		if err := validateSelectorTargets([]string{target}); (err == nil) != ok {
			t.Errorf("%q: err = %v, want ok=%v", target, err, ok)
		}
	}
}

func TestIsCIDRTarget(t *testing.T) {
	for target, want := range map[string]bool{"203.0.113.0/24": true, "2001:db8::/48": true, "203.0.113.7": false, "example.com/24": false, "https://x/1": false} {
		if got := isCIDRTarget(target); got != want {
			t.Errorf("isCIDRTarget(%q) = %v, want %v", target, got, want)
		}
	}
}
