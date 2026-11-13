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
		Internal    *bool  `json:"internal"`
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

// A range is internal when it overlaps a private, link-local or loopback
// block at all, not only when its first address is in one: 172.0.0.0/8
// holds 172.16.0.0/12 and must need a scan zone like 10.0.0.0/8 does.
func TestCIDRInternalSharedWithWeb(t *testing.T) {
	raw, err := os.ReadFile("testdata/cidr_targets.json")
	if err != nil {
		t.Fatal(err)
	}
	var f cidrFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range f.Cases {
		if c.Internal == nil {
			continue
		}
		n++
		v := NewTargetValidator(WithAllowInternalIPs(false), WithMaxCIDRHostBits(c.MaxHostBits))
		got := v.ValidateSingleTarget(c.Target)
		if *c.Internal {
			if got.IsValid || got.Error != "CIDR range contains internal IP addresses" {
				t.Errorf("%s holds internal addresses: valid = %v, error = %q", c.Target, got.IsValid, got.Error)
			}
		} else if !got.IsValid {
			t.Errorf("%s is public: %s", c.Target, got.Error)
		}
	}
	if n < 5 {
		t.Fatalf("only %d internal cases", n)
	}
}

func TestCIDRLocalhostOverlap(t *testing.T) {
	v := NewTargetValidator(WithAllowInternalIPs(true), WithMaxCIDRHostBits(MaxCIDRHostBitsLimit))
	for _, c := range []string{"127.0.0.0/8", "127.1.0.0/16", "::/127"} {
		if r := v.ValidateSingleTarget(c); r.IsValid || r.Error != "CIDR range contains localhost addresses" {
			t.Errorf("%s holds a loopback address: valid = %v, error = %q", c, r.IsValid, r.Error)
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
