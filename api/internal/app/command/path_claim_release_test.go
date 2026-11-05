package command

import (
	"slices"
	"testing"
)

// SECURITY: a sensor can release the ledger claim of an origin only by
// naming, in its result, an origin the job itself was given, with the reason
// no_candidates. Any other gap, or a host outside the job, releases nothing.
func TestEmptyDiscoveryOrigins(t *testing.T) {
	targets := []string{"https://a.example.com", "https://b.example.com:8443", "https://c.example.com"}
	result := func(gaps string) []byte {
		return []byte(`{"metadata":{"coverage_gaps":` + gaps + `,"coverage_gaps_total":3}}`)
	}
	cases := []struct {
		name string
		res  []byte
		want []string
	}{
		{"origin form", result(`[{"host":"https://a.example.com","reason":"no_candidates"}]`), []string{"https://a.example.com"}},
		{"host form with a port", result(`[{"host":"b.example.com:8443","reason":"no_candidates"}]`), []string{"https://b.example.com:8443"}},
		{"another reason", result(`[{"host":"https://a.example.com","reason":"catch_all"},{"host":"https://c.example.com","reason":"budget"}]`), nil},
		{"a host the job was not given", result(`[{"host":"https://evil.example.com","reason":"no_candidates"}]`), nil},
		{"a path is not a host", result(`[{"host":"https://a.example.com/x","reason":"no_candidates"}]`), nil},
		{"only one of two", result(`[{"host":"https://a.example.com","reason":"no_candidates"},{"host":"https://c.example.com","reason":"throttled"}]`), []string{"https://a.example.com"}},
		{"no gaps", []byte(`{"metadata":{}}`), nil},
		{"not json", []byte(`x`), nil},
	}
	for _, c := range cases {
		if got := emptyDiscoveryOrigins(targets, c.res); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
