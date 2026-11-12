package user

import (
	"encoding/json"
	"testing"
)

func TestFindingsInformationalPreference(t *testing.T) {
	var p Preferences
	if got := p.FindingsInformational(); got != FindingsInformationalDefault {
		t.Fatalf("unset = %q, want default", got)
	}
	for _, v := range []string{FindingsInformationalInclude, FindingsInformationalExclude, FindingsInformationalDefault} {
		got := p.WithFindingsInformational(v)
		if got.FindingsInformational() != v {
			t.Errorf("WithFindingsInformational(%q) reads back %q", v, got.FindingsInformational())
		}
		// Stored as JSONB: the choice survives a round trip.
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var back Preferences
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if back.FindingsInformational() != v {
			t.Errorf("%q after JSON = %q (%s)", v, back.FindingsInformational(), raw)
		}
	}
	if got := p.WithFindingsInformational("bogus").FindingsInformational(); got != FindingsInformationalDefault {
		t.Errorf("unknown value = %q, want default", got)
	}
}
