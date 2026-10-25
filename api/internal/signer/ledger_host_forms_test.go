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
