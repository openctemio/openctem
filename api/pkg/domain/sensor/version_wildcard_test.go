package sensor

import "testing"

// SECURITY: only a sensor that reads a "*" deny-path segment is sent one; any
// other (older, unknown, development, pre-release) gets the cut form.
func TestReadsWildcardDenyPaths(t *testing.T) {
	for v, want := range map[string]bool{
		"v0.38.2": true, "0.38.2": true, "v0.38.9": true, "v0.37.2": true, "v0.37.5": true, "v0.39.0": true, "v0.40.1": true,
		"v1.0.0": true, "v0.38.2-3-gabcdef1": true,
		"v0.38.1": false, "v0.37.1": false, "v0.36.9": false, "v0.38.2-rc1": false, "dev": false, "": false, "v0.4.2": false,
	} {
		if got := ReadsWildcardDenyPaths(v); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}
