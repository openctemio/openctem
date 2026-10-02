package remediation

import "testing"

func TestDeriveKey(t *testing.T) {
	cases := []struct {
		name      string
		in        KeyInput
		wantOK    bool
		wantKey   string
		wantTitle string
	}{
		{
			name:      "SCA groups by component when a fix exists",
			in:        KeyInput{ComponentKey: "pkg:npm/lodash", FixAvailable: true},
			wantOK:    true,
			wantKey:   "sca:pkg:npm/lodash",
			wantTitle: "Upgrade pkg:npm/lodash",
		},
		{
			name:   "SCA without a fix is not groupable",
			in:     KeyInput{ComponentKey: "pkg:npm/lodash", FixAvailable: false},
			wantOK: false,
		},
		{
			name:    "host groups by normalized solution",
			in:      KeyInput{SolutionText: "  Upgrade OpenSSL to 3.0.7  "},
			wantOK:  true,
			wantKey: "sol:" + sha256Hex("upgrade openssl to 3.0.7"),
		},
		{
			name:   "no signal is not groupable",
			in:     KeyInput{},
			wantOK: false,
		},
		{
			name:      "SCA takes precedence over solution text",
			in:        KeyInput{ComponentKey: "pkg:npm/lodash", FixAvailable: true, SolutionText: "do something"},
			wantOK:    true,
			wantKey:   "sca:pkg:npm/lodash",
			wantTitle: "Upgrade pkg:npm/lodash",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, title, ok := DeriveKey(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if key != tc.wantKey {
				t.Errorf("key = %q, want %q", key, tc.wantKey)
			}
			if tc.wantTitle != "" && title != tc.wantTitle {
				t.Errorf("title = %q, want %q", title, tc.wantTitle)
			}
		})
	}
}

// Two renderings of the same solution (case/whitespace) must map to one key.
func TestDeriveKey_NormalizationStable(t *testing.T) {
	a, _, _ := DeriveKey(KeyInput{SolutionText: "Update the RHEL kernel package"})
	b, _, _ := DeriveKey(KeyInput{SolutionText: "  update   the RHEL   Kernel Package  "})
	if a != b {
		t.Errorf("expected same key for equivalent solutions, got %q vs %q", a, b)
	}
}

func sha256Hex(s string) string {
	// mirror DeriveKey's hash for the expectation
	key, _, _ := DeriveKey(KeyInput{SolutionText: s})
	return key[len("sol:"):]
}
