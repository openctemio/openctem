package signer

// The signer is the independent last check: a domain entry signs host
// names only, and a public network or a numeric-notation address always
// needs an entry, whatever the API decided.

import "testing"

func TestLedger_URLWithScopedSuffixInPathIsNotSigned(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))))
	for _, target := range []string{
		"http://other.test/?q=.example.com",
		"https://other.test/#.example.com",
		"http://other.test/a/b.example.com",
	} {
		wantReason(t, signTargets(s, "nuclei", target), ReasonOutOfLedger)
	}
	if ref := signTargets(s, "nuclei", "https://app.example.com/login"); ref != nil {
		t.Fatalf("scoped URL refused: %+v", ref)
	}
}

func TestLedger_PublicNetworksAndNumericHostsNeedAnEntry(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))))
	for _, target := range []string{"0.0.0.0/0", "10.0.0.0/1", "http://2852039166/"} {
		wantReason(t, signTargets(s, "nuclei", target), ReasonOutOfLedger)
	}
}

// Label-boundary vectors at the signer: a lookalike of a ledger entry's name
// is never signed, in any spelling, and one tenant's entry signs nothing for
// another tenant.
func TestLedger_LabelBoundary(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))))
	for _, target := range []string{"APP.Example.COM.", "example.com:8443", "https://app.example.com.:8443/x", "xn--e1afmkfd.example.com"} {
		if ref := signTargets(s, "nuclei", target); ref != nil {
			t.Fatalf("%q refused: %+v", target, ref)
		}
	}
	for _, target := range []string{
		"notexample.com", "notexample.com:443", "https://notexample.com/", "example.com.evil.test",
		"https://app.example.com.evil.test:8443/", "example.com@evil.test", "https://example.com@evil.test/",
		"evil-example.com", "https://evil.test/?h=app.example.com",
	} {
		wantReason(t, signTargets(s, "nuclei", target), ReasonOutOfLedger)
	}
	// Another tenant's job with an in-entry name in any spelling.
	for _, target := range []string{"app.example.com", "https://app.example.com/", "app.example.com:443"} {
		_, ref := s.Sign(statement(func(m map[string]any) {
			m["tenant_id"] = "99999999-9999-4999-8999-999999999999"
			m["targets"] = []string{target}
		}))
		wantReason(t, ref, ReasonOutOfLedger)
	}
}
