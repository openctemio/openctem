package tenant

import "testing"

func TestScopeSettingsAddressMode(t *testing.T) {
	if got := (ScopeSettings{}).AddressMode(); got != AddressAutoStrong {
		t.Fatalf("default = %q, want auto_strong", got)
	}
	if got := (ScopeSettings{}).AddressModeIn(true); got != AddressAsk {
		t.Fatalf("under Strict = %q, want ask (nothing automatic)", got)
	}
	if got := (ScopeSettings{AddressAutoAdd: AddressNever}).AddressModeIn(true); got != AddressNever {
		t.Fatalf("never under Strict = %q", got)
	}
	for _, v := range []string{"", AddressAutoStrong, AddressAsk, AddressNever} {
		if err := (ScopeSettings{AddressAutoAdd: v}).Validate(); err != nil {
			t.Fatalf("%q: %v", v, err)
		}
	}
	if err := (ScopeSettings{AddressAutoAdd: "always"}).Validate(); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
}
