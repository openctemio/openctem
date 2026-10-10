package signer

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

func limited(id, typ, pattern, ports, protocol string) *jobsign.LedgerEntry {
	e := entry(id, typ, pattern, 1, nil)
	e.Ports, e.Protocol = ports, protocol
	return e
}

// A port-limited entry in the ledger is as narrow as in the database: it
// covers only targets naming an allowed port, and only tools that stay on
// the target they are given (RFC-065 §16.8).
func TestLedger_PortLimitedEntryNeverCoversTheWholeHost(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil, putEntry(limited(tEntry, "domain", "api.example.com", "8443", "tcp"))))

	wantReason(t, signTargets(s, "naabu", "api.example.com"), ReasonOutOfLedger)
	wantReason(t, signTargets(s, "httpx", "api.example.com:22"), ReasonOutOfLedger)
	wantReason(t, signTargets(s, "httpx", "https://api.example.com/"), ReasonOutOfLedger)
	if ref := signTargets(s, "httpx", "api.example.com:8443", "https://api.example.com:8443/x"); ref != nil {
		t.Fatalf("allowed port refused: %+v", ref)
	}
	// A template scanner could reach other ports from the host: refused.
	wantReason(t, signTargets(s, "nuclei", "api.example.com:8443"), ReasonOutOfLedger)

	// An entry without a limit next to it covers the host for every tool.
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry2, "domain", "api.example.com", 1, nil))))
	if ref := signTargets(s, "nuclei", "api.example.com"); ref != nil {
		t.Fatalf("unlimited entry refused: %+v", ref)
	}
}

func TestLedger_PathLimitedEntryOnlyUnderItsPath(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "url", "https://shop.example.com/api*", 1, nil))))
	if ref := signTargets(s, "httpx", "https://shop.example.com/api/v1"); ref != nil {
		t.Fatalf("url under the path refused: %+v", ref)
	}
	wantReason(t, signTargets(s, "httpx", "https://shop.example.com/admin"), ReasonOutOfLedger)
	wantReason(t, signTargets(s, "httpx", "https://shop.example.com/api/../admin"), ReasonOutOfLedger)
	wantReason(t, signTargets(s, "httpx", "shop.example.com"), ReasonOutOfLedger)
	// A crawler would leave the path: refused.
	wantReason(t, signTargets(s, "katana", "https://shop.example.com/api/"), ReasonOutOfLedger)
}

// Dropping or relaxing a port limit is a widening: it needs the policy's
// approvals. Adding one narrows.
func TestLedger_RelaxingAPortLimitIsAWidening(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil, putEntry(limited(tEntry, "domain", "api.example.com", "8443", "tcp"))))

	_, ref := s.Ledger().Apply(change(1, nil, putEntry(entry(tEntry, "domain", "api.example.com", 1, nil))), tNow)
	wantReason(t, ref, ReasonNotApproved)
	_, ref = s.Ledger().Apply(change(1, nil, putEntry(limited(tEntry, "domain", "api.example.com", "8443-8444", "tcp"))), tNow)
	wantReason(t, ref, ReasonNotApproved)
	wantReason(t, signTargets(s, "naabu", "api.example.com"), ReasonOutOfLedger)

	// A sync from the database never drops a limit: an entry whose limit
	// differs is removed.
	snap := jobsign.LedgerSnapshot{TenantID: tTenant, Entries: []jobsign.LedgerEntry{*entry(tEntry, "domain", "api.example.com", 1, nil)},
		Exclusions: []jobsign.LedgerExclusion{}}
	if _, ref := s.Ledger().Sync(snap, tNow); ref != nil {
		t.Fatal(ref)
	}
	wantReason(t, signTargets(s, "httpx", "api.example.com:8443"), ReasonOutOfLedger)
	wantReason(t, signTargets(s, "naabu", "api.example.com"), ReasonOutOfLedger)
}

func TestLedger_RefusesNonCanonicalPortLimits(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	for name, e := range map[string]*jobsign.LedgerEntry{
		"unsorted":      limited(tEntry, "domain", "api.example.com", "8443,80", ""),
		"bad protocol":  limited(tEntry, "domain", "api.example.com", "80", "sctp"),
		"named list":    limited(tEntry, "domain", "api.example.com", "top-100", ""),
		"url with port": limited(tEntry, "url", "https://a.example.com/x*", "443", ""),
	} {
		if _, ref := s.Ledger().Apply(change(0, nil, putEntry(e)), tNow); ref == nil || ref.reason != ReasonLedgerMalformed {
			t.Errorf("%s: %+v", name, ref)
		}
	}
}
