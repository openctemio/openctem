package handler

import (
	"fmt"
	"slices"
	"testing"
)

// ?count_by adds one GROUP BY per field to the caller's stats query, so it is
// capped and limited to the property schema: a key outside it can only count
// nothing, and an unbounded list is an expensive request any member can send.
func TestStatsCountByFields(t *testing.T) {
	got := statsCountByFields([]string{"is_virtual", " os ", "os_name", "not_a_key", "x_custom", "ssl", "has_mfa"})
	want := []string{"is_virtual", "os_name", "has_mfa"} // os folds into os_name, once
	if !slices.Equal(got, want) {
		t.Errorf("statsCountByFields = %v, want %v", got, want)
	}

	many := []string{"asn", "country", "city", "isp", "hostname", "registrar", "root_domain",
		"domain_level", "port", "protocol", "product", "state", "title", "server"}
	if got := statsCountByFields(many); len(got) != maxStatsCountBy {
		t.Errorf("len = %d, want the cap %d (%v)", len(got), maxStatsCountBy, got)
	}

	var junk []string
	for i := 0; i < 1000; i++ {
		junk = append(junk, fmt.Sprintf("k%d", i))
	}
	if got := statsCountByFields(junk); len(got) != 0 {
		t.Errorf("unknown keys must be dropped, got %v", got)
	}
}
