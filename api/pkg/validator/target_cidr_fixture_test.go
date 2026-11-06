package validator

import (
	"encoding/json"
	"os"
	"testing"
)

// cidrFixture is testdata/cidr_targets.json: the CIDR bounds the web
// console's target format check reads too, so both refuse the same ranges
// with the same words.
type cidrFixture struct {
	Cases []struct {
		Target      string `json:"target"`
		MaxHostBits int    `json:"max_host_bits"`
		Valid       bool   `json:"valid"`
		Reason      string `json:"reason"`
	} `json:"cases"`
}

func TestCIDRBoundsSharedWithWeb(t *testing.T) {
	raw, err := os.ReadFile("testdata/cidr_targets.json")
	if err != nil {
		t.Fatal(err)
	}
	var f cidrFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range f.Cases {
		v := NewTargetValidator(WithAllowInternalIPs(true), WithMaxCIDRHostBits(c.MaxHostBits))
		got := v.ValidateSingleTarget(c.Target)
		if got.IsValid != c.Valid {
			t.Errorf("%s (max %d host bits): valid = %v, want %v (%s)", c.Target, c.MaxHostBits, got.IsValid, c.Valid, got.Error)
			continue
		}
		if !c.Valid && got.Error != c.Reason {
			t.Errorf("%s: reason = %q, want %q", c.Target, got.Error, c.Reason)
		}
	}
}

func TestCIDRBoundDefaultsAndClamp(t *testing.T) {
	if r := NewTargetValidator(WithAllowInternalIPs(true)).ValidateSingleTarget("10.0.0.0/15"); r.IsValid {
		t.Fatal("the default bound is /16: a /15 must be refused")
	}
	// A bound above the platform limit is clamped to /8.
	v := NewTargetValidator(WithAllowInternalIPs(true), WithMaxCIDRHostBits(64))
	if r := v.ValidateSingleTarget("10.0.0.0/7"); r.IsValid {
		t.Fatal("a /7 is wider than the platform limit and must be refused")
	}
	if r := v.ValidateSingleTarget("10.0.0.0/8"); !r.IsValid {
		t.Fatalf("a /8 is the platform limit: %s", r.Error)
	}
}
