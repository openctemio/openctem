package contentpin

import (
	"slices"
	"strconv"
	"testing"
)

// The acceptance names of research 344: from the organization's own names
// charts-uat and hocviendgo5, the learned labels and their permutations hold
// charts-uat2 and hocviendgo, which no passive source reported.
func TestPermutations_AcceptanceNames(t *testing.T) {
	learned := LearnedLabels([]Named{
		{Name: "charts-uat.example.vn", Root: "example.vn"},
		{Name: "hocviendgo5.example.vn", Root: "example.vn"},
		{Name: "dchart-api.example.vn", Root: "example.vn"},
	})
	all := append(slices.Clone(learned), Permutations(learned)...)
	for _, want := range []string{"charts-uat", "charts-uat2", "hocviendgo", "hocviendgo6", "hocviendgo-uat"} {
		if !slices.Contains(all, want) {
			t.Errorf("%q missing from %v", want, all)
		}
	}
	// The names use the environment word uat, so only uat is crossed: dev
	// is not, since the organization does not use it.
	for _, not := range []string{"charts-dev", "dev-charts"} {
		if slices.Contains(all, not) {
			t.Errorf("%q generated though the names use no dev", not)
		}
	}
}

func TestPermutations_Rules(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
		not  []string
	}{
		// Numbered neighbors keep the width; 0 has no lower neighbor.
		{in: []string{"web09"}, want: []string{"web10", "web08"}},
		{in: []string{"api0"}, want: []string{"api1"}, not: []string{"api-1"}},
		// A label ending in an environment word gets numbered copies.
		{in: []string{"portal-stg"}, want: []string{"portal-stg1", "portal-stg2"}},
		// An environment word alone is not numbered (uat2 would be a guess
		// with no base).
		{in: []string{"uat"}, not: []string{"uat1", "uat2"}},
		// No environment word used: the default ones are crossed.
		{in: []string{"shop"}, want: []string{"shop-dev", "dev-shop", "shop-staging"}},
		// Numbers above the bound and pure numbers are left alone.
		{in: []string{"x1000"}, not: []string{"x1001", "x999"}},
	}
	for _, c := range cases {
		got := Permutations(c.in)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("Permutations(%v) = %v, missing %q", c.in, got, w)
			}
		}
		for _, n := range c.not {
			if slices.Contains(got, n) {
				t.Errorf("Permutations(%v) = %v, has %q", c.in, got, n)
			}
		}
	}
}

// Every permutation is a valid, new DNS label; the output is bounded and the
// same for the same input (retries of one run pin the same list).
func TestPermutations_BoundedValidDeterministic(t *testing.T) {
	learned := []string{"dev", "uat", "prod", "a.b"}
	for i := range 5000 {
		learned = append(learned, "svc"+strconv.Itoa(i)+"x", "app-"+strconv.Itoa(i)+"-uat")
	}
	learned = append(learned, "this-label-is-exactly-sixty-three-characters-long-to-test-uat-x")
	got := Permutations(learned)
	if len(got) == 0 || len(got) > maxPermutations {
		t.Fatalf("%d permutations", len(got))
	}
	have := map[string]bool{}
	for _, l := range learned {
		have[l] = true
	}
	for _, l := range got {
		if !labelRE.MatchString(l) || have[l] {
			t.Fatalf("invalid or repeated label %q", l)
		}
		have[l] = true
	}
	if !slices.Equal(got, Permutations(learned)) {
		t.Fatal("not deterministic")
	}
}
