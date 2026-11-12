package easmseed

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeASN(t *testing.T) {
	ok := map[string]string{"AS13335": "AS13335", "as3333": "AS3333", " 15169 ": "AS15169", "4199999999": "AS4199999999"}
	for in, want := range ok {
		got, err := NormalizeASN(in)
		if err != nil || got != want {
			t.Errorf("NormalizeASN(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "AS", "AS0", "ASx", "-1", "AS23456", "AS64512", "AS65534", "AS64500", "AS4200000000", "AS4294967296", "AS65535"} {
		if _, err := NormalizeASN(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeASN(%q) accepted", bad)
		}
	}
}

func TestNormalizeOrgName(t *testing.T) {
	if got, err := NormalizeOrgName("  Example   Corp  "); err != nil || got != "Example Corp" {
		t.Fatalf("got %q %v", got, err)
	}
	for _, bad := range []string{"ab", "", "x\x00yz", strings.Repeat("a", 201)} {
		if _, err := NormalizeOrgName(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeOrgName(%q) accepted", bad)
		}
	}
	if _, err := Normalize("cidr", "10.0.0.0/8"); !errors.Is(err, ErrInvalid) {
		t.Error("unknown kind accepted")
	}
}
