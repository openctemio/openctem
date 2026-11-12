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

func signLimited(s *Service, tool string, limits []map[string]any, targets ...string) *refusal {
	_, ref := s.Sign(statement(func(m map[string]any) {
		m["tool"], m["targets"] = tool, targets
		if limits != nil {
			m["limits"] = limits
		}
	}))
	return ref
}

// SECURITY: a crawler or template scanner on a target only limited entries
// cover is signed only with scope limits in the statement, and only limits
// each within an approved entry that covers the target (the sensor
// enforces them): never another port, a wider path or another host.
func TestLedger_LimitedTargetSignedWithLimitsWithinTheLedger(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil,
		putEntry(entry(tEntry, "url", "https://shop.example.com/api*", 1, nil)),
		putEntry(limited(tEntry2, "domain", "api.example.com", "8443,9000-9010", "tcp"))))

	pathLimit := []map[string]any{{"host": "shop.example.com", "ports": "443", "protocol": "tcp", "path_prefix": "/api"}}
	if ref := signLimited(s, "katana", pathLimit, "https://shop.example.com/api/"); ref != nil {
		t.Fatalf("crawler inside the path refused: %+v", ref)
	}
	narrower := []map[string]any{{"host": "shop.example.com", "ports": "443", "protocol": "tcp", "path_prefix": "/api/v2"}}
	if ref := signLimited(s, "katana", narrower, "https://shop.example.com/api/"); ref != nil {
		t.Fatalf("a narrower path refused: %+v", ref)
	}
	if ref := signLimited(s, "nuclei", []map[string]any{{"host": "api.example.com", "ports": "8443", "protocol": "tcp"}}, "api.example.com:8443"); ref != nil {
		t.Fatalf("template scanner inside the port refused: %+v", ref)
	}
	for name, lim := range map[string][]map[string]any{
		"no limits":    nil,
		"root path":    {{"host": "shop.example.com", "ports": "443", "protocol": "tcp", "path_prefix": "/"}},
		"sibling path": {{"host": "shop.example.com", "ports": "443", "protocol": "tcp", "path_prefix": "/apiadmin"}},
		"no path":      {{"host": "shop.example.com", "ports": "443", "protocol": "tcp"}},
		"other port":   {{"host": "shop.example.com", "ports": "8443", "protocol": "tcp", "path_prefix": "/api"}},
		"any protocol": {{"host": "shop.example.com", "ports": "443", "path_prefix": "/api"}},
	} {
		if ref := signLimited(s, "katana", lim, "https://shop.example.com/api/"); ref == nil || ref.reason != ReasonOutOfLedger {
			t.Errorf("%s: %+v", name, ref)
		}
	}
	for name, lim := range map[string][]map[string]any{
		"wider ports": {{"host": "api.example.com", "ports": "8443-9010", "protocol": "tcp"}},
		"every port":  {{"host": "api.example.com", "protocol": "tcp"}},
		"udp":         {{"host": "api.example.com", "ports": "8443", "protocol": "udp"}},
	} {
		if ref := signLimited(s, "nuclei", lim, "api.example.com:8443"); ref == nil || ref.reason != ReasonOutOfLedger {
			t.Errorf("%s: %+v", name, ref)
		}
	}
	// Malformed limits, or limits for a host the job does not target.
	for name, lim := range map[string][]map[string]any{
		"other host":     {{"host": "evil.example.org", "ports": "443"}},
		"not canonical":  {{"host": "shop.example.com", "ports": "443,80"}},
		"dot segment":    {{"host": "shop.example.com", "ports": "443", "path_prefix": "/api/../admin"}},
		"encoded":        {{"host": "shop.example.com", "ports": "443", "path_prefix": "/api%2fx"}},
		"limits nothing": {{"host": "shop.example.com"}},
		"empty list":     {},
	} {
		if ref := signLimited(s, "katana", lim, "https://shop.example.com/api/"); ref == nil || ref.reason != ReasonBadLimits {
			t.Errorf("%s: %+v", name, ref)
		}
	}
}
