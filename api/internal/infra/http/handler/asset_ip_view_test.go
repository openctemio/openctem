package handler

import "testing"

func TestAddressNetwork(t *testing.T) {
	for in, want := range map[string]string{
		"10.1.2.3":        "10.1.2.0/24",
		"[2001:db8::1]":   "2001:db8::/64",
		"::ffff:10.1.2.3": "10.1.2.0/24",
		"10.1.2.0/24":     "",
		"api.example.com": "",
		"fe80::1%eth0":    "",
	} {
		if got := addressNetwork(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
