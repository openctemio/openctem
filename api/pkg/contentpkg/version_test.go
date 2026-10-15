package contentpkg

import (
	"encoding/json"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseVersion(t *testing.T) {
	for _, ok := range []string{"0.1.0", "1.4.0", "2.0.0-rc.1", "10.20.30"} {
		if _, err := ParseVersion(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "1", "1.2", "v1.2.3", "01.2.3", "1.2.3+build", "1.2.3-", "1.2.3 "} {
		if _, err := ParseVersion(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestRange(t *testing.T) {
	cases := []struct {
		rng, v string
		want   bool
	}{
		{">=0.9.0, <2.0.0", "0.9.7", true},
		{">=0.9.0, <2.0.0", "2.0.0", false},
		{">=0.9.0, <2.0.0", "0.8.9", false},
		{">=3", "3.0.0", true},
		{">=3", "2.9.9", false},
		{"=1.2.3", "1.2.3", true},
		{"=1.2.3", "1.2.4", false},
		{">1.0.0,<=1.1", "1.1.0", true},
		{">=1.0.0", "2.0.0-rc.1", false},             // a pre-release needs a named pre-release
		{">=2.0.0-rc.1, <3.0.0", "2.0.0-rc.2", true}, // same MAJOR.MINOR.PATCH
		{">=2.0.0-rc.1, <3.0.0", "2.1.0-beta.1", false},
	}
	for _, c := range cases {
		got, err := Satisfies(c.rng, c.v)
		if err != nil {
			t.Fatalf("%s %s: %v", c.rng, c.v, err)
		}
		if got != c.want {
			t.Fatalf("%s contains %s = %v, want %v", c.rng, c.v, got, c.want)
		}
	}
	if ok, err := Satisfies(">=0.9.0", "v0.9.7"); err != nil || !ok {
		t.Fatal("a v-prefixed release satisfies")
	}
	for _, bad := range []string{"", "^1.0.0", "~1.2", "1.0.0", ">=1.0.0 || <0.5.0", ">=a", ">=1,>=1,>=1,>=1,>=1"} {
		if _, err := ParseRange(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	if CompareVersions("1.10.0", "1.9.0") <= 0 || CompareVersions("1.0.0-rc.1", "1.0.0") >= 0 ||
		CompareVersions("1.0.0", "1.0.0") != 0 || CompareVersions("bad", "1.0.0") >= 0 {
		t.Fatal("ordering")
	}
}
