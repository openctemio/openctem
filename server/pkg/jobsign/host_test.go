package jobsign

import "testing"

func TestNumericHost(t *testing.T) {
	for host, want := range map[string]bool{
		"2130706433": true, "0x7f.1": true, "0x7f000001": true, "127.1": true, "0177.0.0.1": true,
		"10.0.0.1.": true, "0x": true, "www.example.com": false, "example.com": false,
		"1password.com": false, "a.0xzz": false, "3com": false, "": false,
	} {
		if got := NumericHost(host); got != want {
			t.Errorf("%q: got %v, want %v", host, got, want)
		}
	}
}
