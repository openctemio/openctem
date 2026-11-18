package cirun

import "testing"

func TestSharedIssuer(t *testing.T) {
	for issuer, shared := range map[string]bool{
		"https://gitlab.com":                          true,
		"https://staging.gitlab.com":                  true,
		"https://token.actions.githubusercontent.com": true,
		"https://gitlab.example.com":                  false,
		"https://notgitlab.com":                       false,
		"https://gitlab.com.example.org":              false,
		"":                                            true,
		// Hosted GitLab operated for others, GitHub data residency.
		"https://jihulab.com":                   true,
		"https://gitlab.cn":                     true,
		"https://example.ghe.com":               true,
		"https://token.actions.example.ghe.com": true,
		"https://notghe.com":                    false,
	} {
		if got := SharedIssuer(issuer); got != shared {
			t.Errorf("SharedIssuer(%q) = %v, want %v", issuer, got, shared)
		}
	}
}
