package weblink

import "testing"

const org = "6f1c2a9e-3b7d-4c55-9a0e-1d2f3a4b5c6d"

func TestWithOrg(t *testing.T) {
	cases := []struct{ name, in, org, want string }{
		{"detail path", "/emerging-threats/abc", org, "/emerging-threats/abc?org=" + org},
		{"keeps query", "/findings?sort=-priority", org, "/findings?org=" + org + "&sort=-priority"},
		{"keeps fragment", "/scope#approvers", org, "/scope?org=" + org + "#approvers"},
		{"absolute", "https://ctem.example.com/findings/1", org, "https://ctem.example.com/findings/1?org=" + org},
		{"replaces a forged org", "/findings/1?org=other", org, "/findings/1?org=" + org},
		{"empty link", "", org, ""},
		{"empty org", "/findings/1", "", "/findings/1"},
		{"blank org", "/findings/1", "  ", "/findings/1"},
		{"unparsable", "/%zz", org, "/%zz"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := WithOrg(c.in, c.org); got != c.want {
				t.Errorf("WithOrg(%q, %q) = %q, want %q", c.in, c.org, got, c.want)
			}
		})
	}
}

func TestAbsolute(t *testing.T) {
	cases := []struct{ name, base, in, want string }{
		{"joins", "https://ctem.example.com/", "/findings/1", "https://ctem.example.com/findings/1"},
		{"already absolute", "https://ctem.example.com", "https://other.example/x", "https://other.example/x"},
		{"protocol relative stays", "https://ctem.example.com", "//evil.example/x", "//evil.example/x"},
		{"no base", "", "/findings/1", "/findings/1"},
		{"empty link", "https://ctem.example.com", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Absolute(c.base, c.in); got != c.want {
				t.Errorf("Absolute(%q, %q) = %q, want %q", c.base, c.in, got, c.want)
			}
		})
	}
}

func TestConsole(t *testing.T) {
	got := Console("https://ctem.example.com", "/emerging-threats", org)
	if want := "https://ctem.example.com/emerging-threats?org=" + org; got != want {
		t.Fatalf("Console = %q, want %q", got, want)
	}
}
