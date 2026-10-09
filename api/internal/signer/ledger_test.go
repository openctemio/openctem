package signer

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Hostile-caller tests of the scope ledger (RFC-040 §5.6 points 4 and 5):
// the API process or its database is assumed to be the attacker.

const (
	tAdminA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tAdminB    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	tAdminC    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	tEntry     = "e0000000-0000-4000-8000-000000000001"
	tEntry2    = "e0000000-0000-4000-8000-000000000002"
	tExclusion = "e0000000-0000-4000-8000-0000000000e1"
	tChange    = "c0000000-0000-4000-8000-000000000001"
)

func enforcing(c *Config) { c.LedgerMode = jobsign.LedgerEnforce }

func entry(id, typ, pattern string, tier int, exp *time.Time) *jobsign.LedgerEntry {
	return &jobsign.LedgerEntry{ID: id, Type: typ, Pattern: pattern, MaxTier: tier, ExpiresAt: exp}
}

// change is a change requested by admin A with the given approvers.
func change(required int, approvers []string, ops ...jobsign.LedgerOp) jobsign.LedgerChange {
	ch := jobsign.LedgerChange{TenantID: tTenant, ChangeID: tChange, Requester: tAdminA, RequiredApprovals: required, Ops: ops,
		Approvals: []jobsign.LedgerApproval{}}
	for _, a := range approvers {
		ch.Approvals = append(ch.Approvals, jobsign.LedgerApproval{UserID: a, ApprovedAt: tNow.Add(-time.Minute)})
	}
	return ch
}

func putEntry(e *jobsign.LedgerEntry) jobsign.LedgerOp {
	return jobsign.LedgerOp{Op: jobsign.OpPutEntry, Entry: e}
}

func mustApply(t *testing.T, s *Service, ch jobsign.LedgerChange) string {
	t.Helper()
	res, ref := s.Ledger().Apply(ch, tNow)
	if ref != nil {
		t.Fatalf("change refused: %+v", ref)
	}
	return res.Kind
}

// signTargets signs a statement for tool and targets.
func signTargets(s *Service, tool string, targets ...string) *refusal {
	_, ref := s.Sign(statement(func(m map[string]any) { m["tool"] = tool; m["targets"] = targets }))
	return ref
}

func wantReason(t *testing.T, ref *refusal, reason string) {
	t.Helper()
	if ref == nil || ref.reason != reason {
		t.Fatalf("want refusal %s, got %+v", reason, ref)
	}
}

// A command row written straight into the database (or an API that asks for
// anything) names a target nobody approved: the signer does not sign it.
func TestLedger_OutOfLedgerTargetIsNotSigned(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	wantReason(t, signTargets(s, "nuclei", "victim.example.org"), ReasonOutOfLedger)

	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))))
	if ref := signTargets(s, "nuclei", "example.com", "app.example.com", "https://api.example.com:8443/x"); ref != nil {
		t.Fatalf("in-ledger targets refused: %+v", ref)
	}
	// One target outside is enough to refuse the whole job.
	wantReason(t, signTargets(s, "nuclei", "app.example.com", "victim.example.org"), ReasonOutOfLedger)
	// Another tenant's ledger never counts.
	_, ref := s.Sign(statement(func(m map[string]any) {
		m["tenant_id"] = "99999999-9999-4999-8999-999999999999"
		m["targets"] = []string{"app.example.com"}
	}))
	wantReason(t, ref, ReasonOutOfLedger)
}

func TestLedger_CIDRTierPassiveAndInternalTargets(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "cidr", "203.0.113.0/24", 1, nil))))
	if ref := signTargets(s, "nuclei", "203.0.113.10", "203.0.113.0/25"); ref != nil {
		t.Fatalf("addresses inside the range refused: %+v", ref)
	}
	wantReason(t, signTargets(s, "nuclei", "203.0.113.0/23"), ReasonOutOfLedger)
	// An intrusive tool needs a t2 entry.
	wantReason(t, signTargets(s, "zap", "203.0.113.10"), ReasonTierExceedsLedge)
	// A passive tool sends nothing to its targets: no entry needed (RFC-054
	// §4.2), as on the API side.
	if ref := signTargets(s, "subfinder", "elsewhere.example.net"); ref != nil {
		t.Fatalf("passive tool refused: %+v", ref)
	}
	// Private addresses and internal names are gated by zones, not entries.
	if ref := signTargets(s, "nuclei", "10.1.2.3", "db.internal"); ref != nil {
		t.Fatalf("internal targets refused: %+v", ref)
	}
}

func TestLedger_WideningNeedsThePolicyApprovals(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	op := putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))

	// One approval under a two-approval policy.
	_, ref := s.Ledger().Apply(change(2, []string{tAdminB}, op), tNow)
	wantReason(t, ref, ReasonNotApproved)
	// The requester approving their own widening does not count.
	_, ref = s.Ledger().Apply(change(2, []string{tAdminA, tAdminB}, op), tNow)
	wantReason(t, ref, ReasonNotApproved)
	_, ref = s.Ledger().Apply(change(1, []string{tAdminA}, op), tNow)
	wantReason(t, ref, ReasonNotApproved)
	// The same person twice is malformed.
	_, ref = s.Ledger().Apply(change(2, []string{tAdminB, tAdminB}, op), tNow)
	wantReason(t, ref, ReasonLedgerMalformed)
	wantReason(t, signTargets(s, "nuclei", "app.example.com"), ReasonOutOfLedger)

	if k := mustApply(t, s, change(2, []string{tAdminB, tAdminC}, op)); k != jobsign.ChangeWiden {
		t.Fatalf("kind %s", k)
	}
	if ref := signTargets(s, "nuclei", "app.example.com"); ref != nil {
		t.Fatalf("approved entry refused: %+v", ref)
	}
}

func TestLedger_IntrusiveEntryNeedsOneApprovalAndTheOperatorFloor(t *testing.T) {
	exp := tNow.Add(7 * 24 * time.Hour)
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	// The policy says 0, but an intrusive entry never widens without one.
	_, ref := s.Ledger().Apply(change(0, nil, putEntry(entry(tEntry, "domain", "app.example.com", 2, &exp))), tNow)
	wantReason(t, ref, ReasonNotApproved)
	// A t2 entry without an expiry is malformed.
	_, ref = s.Ledger().Apply(change(1, []string{tAdminB}, putEntry(entry(tEntry, "domain", "app.example.com", 2, nil))), tNow)
	wantReason(t, ref, ReasonLedgerMalformed)

	floor := newService(t, t.TempDir(), newKey(t), func(c *Config) { enforcing(c); c.LedgerMinApprovals = 2 })
	_, ref = floor.Ledger().Apply(change(0, []string{tAdminB}, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))), tNow)
	wantReason(t, ref, ReasonNotApproved)
}

func TestLedger_SelfApprovalCountsOnceForTheRequester(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	op := putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))
	ch := change(1, nil, op)
	ch.Approvals = []jobsign.LedgerApproval{{UserID: tAdminA, ApprovedAt: tNow, SelfApproved: true}}
	mustApply(t, s, ch)

	// A self-approval by someone else is malformed.
	ch.Approvals = []jobsign.LedgerApproval{{UserID: tAdminB, ApprovedAt: tNow, SelfApproved: true}}
	ch.Ops = []jobsign.LedgerOp{putEntry(entry(tEntry2, "domain", "*.example.net", 1, nil))}
	_, ref := s.Ledger().Apply(ch, tNow)
	wantReason(t, ref, ReasonLedgerMalformed)
}

func TestLedger_NarrowingAppliesWithoutApprovals(t *testing.T) {
	exp := tNow.Add(24 * time.Hour)
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(2, []string{tAdminB, tAdminC}, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))))

	// A shorter life is narrowing: no approval needed even under policy 2.
	if k := mustApply(t, s, change(2, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, &exp)))); k != jobsign.ChangeNarrow {
		t.Fatalf("kind %s, want narrow", k)
	}
	// Removing it again: no approval, and nothing is signed afterwards.
	if k := mustApply(t, s, change(2, nil, jobsign.LedgerOp{Op: jobsign.OpRemoveEntry, ID: tEntry})); k != jobsign.ChangeNarrow {
		t.Fatalf("kind %s, want narrow", k)
	}
	wantReason(t, signTargets(s, "nuclei", "app.example.com"), ReasonOutOfLedger)

	// Raising a tier or extending an expiry is a widening even when the API
	// calls it an update.
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, &exp))))
	later := exp.Add(time.Hour)
	_, ref := s.Ledger().Apply(change(1, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, &later))), tNow)
	wantReason(t, ref, ReasonNotApproved)
	_, ref = s.Ledger().Apply(change(1, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))), tNow)
	wantReason(t, ref, ReasonNotApproved)
}

func TestLedger_ExpiredEntryStopsAuthorizing(t *testing.T) {
	exp := tNow.Add(time.Hour)
	clock := tNow
	s := newService(t, t.TempDir(), newKey(t), func(c *Config) {
		enforcing(c)
		c.Now = func() time.Time { return clock }
	})
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "app.example.com", 1, &exp))))
	if ref := signTargets(s, "nuclei", "app.example.com"); ref != nil {
		t.Fatalf("refused before expiry: %+v", ref)
	}
	clock = exp.Add(time.Second)
	_, ref := s.Sign(statement(func(m map[string]any) {
		m["targets"] = []string{"app.example.com"}
		m["issued_at"] = clock.Format(time.RFC3339Nano)
		m["expires_at"] = clock.Add(time.Hour).Format(time.RFC3339Nano)
	}))
	wantReason(t, ref, ReasonOutOfLedger)
}

func TestLedger_ExclusionAddedAfterApprovalBlocksSigning(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))))
	x := &jobsign.LedgerExclusion{ID: tExclusion, Type: "domain", Pattern: "prod.example.com"}
	// Adding an exclusion narrows: no approval needed.
	if k := mustApply(t, s, change(2, nil, jobsign.LedgerOp{Op: jobsign.OpPutExclusion, Exclusion: x})); k != jobsign.ChangeNarrow {
		t.Fatalf("kind %s, want narrow", k)
	}
	wantReason(t, signTargets(s, "nuclei", "https://prod.example.com/login"), ReasonTargetExcluded)
	// Exclusions bind passive tools too.
	wantReason(t, signTargets(s, "subfinder", "prod.example.com"), ReasonTargetExcluded)
	if ref := signTargets(s, "nuclei", "app.example.com"); ref != nil {
		t.Fatalf("other names refused: %+v", ref)
	}
	// Removing the exclusion widens: it needs the approval.
	_, ref := s.Ledger().Apply(change(1, nil, jobsign.LedgerOp{Op: jobsign.OpRemoveExclusion, ID: tExclusion}), tNow)
	wantReason(t, ref, ReasonNotApproved)
	// So does shortening it.
	soon := tNow.Add(time.Hour)
	short := *x
	short.ExpiresAt = &soon
	_, ref = s.Ledger().Apply(change(1, nil, jobsign.LedgerOp{Op: jobsign.OpPutExclusion, Exclusion: &short}), tNow)
	wantReason(t, ref, ReasonNotApproved)
	mustApply(t, s, change(1, []string{tAdminB}, jobsign.LedgerOp{Op: jobsign.OpRemoveExclusion, ID: tExclusion}))
	if ref := signTargets(s, "nuclei", "prod.example.com"); ref != nil {
		t.Fatalf("still excluded after an approved removal: %+v", ref)
	}
}

func TestLedger_SyncNeverWidens(t *testing.T) {
	exp := tNow.Add(24 * time.Hour)
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	mustApply(t, s, change(0, nil,
		putEntry(entry(tEntry, "domain", "*.example.com", 1, &exp)),
		putEntry(entry(tEntry2, "domain", "*.example.net", 1, nil))))

	// The snapshot (hostile or stale) holds a new entry, a later expiry and
	// a higher tier: none of it is taken; the entry it no longer holds goes.
	snap := jobsign.LedgerSnapshot{TenantID: tTenant, Entries: []jobsign.LedgerEntry{
		*entry(tEntry, "domain", "*.example.com", 2, ptr(exp.Add(time.Hour))),
		*entry("e0000000-0000-4000-8000-000000000003", "domain", "*.victim.example", 1, nil),
	}, Exclusions: []jobsign.LedgerExclusion{}}
	res, ref := s.Ledger().Sync(snap, tNow)
	if ref != nil {
		t.Fatal(ref)
	}
	if res.Narrowed != 1 || res.Diverged != 2 {
		t.Fatalf("sync %+v, want 1 narrowed (example.net removed) and 2 diverged", res)
	}
	wantReason(t, signTargets(s, "nuclei", "app.victim.example"), ReasonOutOfLedger)
	wantReason(t, signTargets(s, "nuclei", "app.example.net"), ReasonOutOfLedger)
	wantReason(t, signTargets(s, "zap", "app.example.com"), ReasonTierExceedsLedge)

	// A narrower snapshot narrows: an exclusion is added, the tier lowered.
	snap = jobsign.LedgerSnapshot{TenantID: tTenant,
		Entries:    []jobsign.LedgerEntry{*entry(tEntry, "domain", "*.example.com", 0, &exp)},
		Exclusions: []jobsign.LedgerExclusion{{ID: tExclusion, Type: "domain", Pattern: "prod.example.com"}}}
	if res, ref = s.Ledger().Sync(snap, tNow); ref != nil || res.Narrowed != 2 {
		t.Fatalf("narrowing sync %+v %+v", res, ref)
	}
	wantReason(t, signTargets(s, "nuclei", "app.example.com"), ReasonTierExceedsLedge)
	wantReason(t, signTargets(s, "subfinder", "prod.example.com"), ReasonTargetExcluded)
}

func ptr[T any](v T) *T { return &v }

func TestLedger_RefusesMalformedAndOversizedChanges(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	cases := map[string]jobsign.LedgerChange{
		"no ops": change(0, nil),
		"bad tenant": func() jobsign.LedgerChange {
			c := change(0, nil, jobsign.LedgerOp{Op: jobsign.OpRemoveEntry, ID: tEntry})
			c.TenantID = "x"
			return c
		}(),
		"bad change id": func() jobsign.LedgerChange {
			c := change(0, nil, jobsign.LedgerOp{Op: jobsign.OpRemoveEntry, ID: tEntry})
			c.ChangeID = ""
			return c
		}(),
		"policy 3":       change(3, nil, jobsign.LedgerOp{Op: jobsign.OpRemoveEntry, ID: tEntry}),
		"unknown op":     change(0, nil, jobsign.LedgerOp{Op: "grant_all"}),
		"bad type":       change(0, nil, putEntry(entry(tEntry, "anything", "x", 1, nil))),
		"bad pattern":    change(0, nil, putEntry(entry(tEntry, "domain", "not a domain", 1, nil))),
		"bad tier":       change(0, nil, putEntry(entry(tEntry, "domain", "a.example.com", 3, nil))),
		"newline":        change(0, nil, putEntry(entry(tEntry, "url", "https://a.example.com/\nx", 1, nil))),
		"path exclusion": change(0, nil, jobsign.LedgerOp{Op: jobsign.OpPutExclusion, Exclusion: &jobsign.LedgerExclusion{ID: tExclusion, Type: "path", Pattern: "x"}}),
		"two items":      change(0, nil, jobsign.LedgerOp{Op: jobsign.OpPutEntry, Entry: entry(tEntry, "domain", "a.example.com", 1, nil), ID: tEntry}),
	}
	for name, ch := range cases {
		if _, ref := s.Ledger().Apply(ch, tNow); ref == nil || ref.reason != ReasonLedgerMalformed {
			t.Errorf("%s: want %s, got %+v", name, ReasonLedgerMalformed, ref)
		}
	}
	ops := make([]jobsign.LedgerOp, jobsign.MaxLedgerOps+1)
	for i := range ops {
		ops[i] = jobsign.LedgerOp{Op: jobsign.OpRemoveEntry, ID: tEntry}
	}
	if _, ref := s.Ledger().Apply(change(0, nil, ops...), tNow); ref == nil {
		t.Error("an oversized change was accepted")
	}
}

func TestLedger_HTTPRefusesUnknownFieldsAndMethods(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), enforcing)
	h := s.Handler()
	body := `{"tenant_id":"` + tTenant + `","change_id":"` + tChange + `","requester":"","approvals":[],"policy_required_approvals":0,` +
		`"ops":[{"op":"put_entry","entry":{"id":"` + tEntry + `","type":"domain","pattern":"*.example.com","max_tier":1}}],"kind":"narrow"}`
	rec := serve(h, "POST", jobsign.LedgerApplyPath, body)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), ReasonLedgerMalformed) {
		t.Fatalf("unknown field (a caller-chosen kind): %d %s", rec.Code, rec.Body)
	}
	body = strings.Replace(body, `,"kind":"narrow"`, "", 1)
	if rec = serve(h, "POST", jobsign.LedgerApplyPath, body); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"kind":"widen"`) {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body)
	}
	if rec = serve(h, "GET", jobsign.LedgerApplyPath, ""); rec.Code != 405 {
		t.Fatalf("GET apply: %d", rec.Code)
	}
	rec = serve(h, "GET", jobsign.LedgerPath, "")
	var st jobsign.LedgerStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.Mode != jobsign.LedgerEnforce || len(st.Tenants) != 1 || st.Tenants[0] != tTenant {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
}

func TestLedger_LogChainVerifiesAndDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	s := newService(t, dir, key, enforcing)
	mustApply(t, s, change(0, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))))
	mustApply(t, s, change(0, nil, jobsign.LedgerOp{Op: jobsign.OpPutExclusion,
		Exclusion: &jobsign.LedgerExclusion{ID: tExclusion, Type: "domain", Pattern: "prod.example.com"}}))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, LedgerLogFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, n, err := VerifyLedgerLog(bytes.NewReader(raw)); err != nil || n != 3 {
		t.Fatalf("verify: %d records, %v", n, err)
	}

	// The state survives a restart (replayed from the log).
	s2 := newService(t, dir, key, enforcing)
	if ref := signTargets(s2, "nuclei", "app.example.com"); ref != nil {
		t.Fatalf("after restart: %+v", ref)
	}
	wantReason(t, signTargets(s2, "nuclei", "prod.example.com"), ReasonTargetExcluded)
	_ = s2.Close()

	// Widening an entry in place, dropping a line, or rewriting it
	// consistently without the chain: the log no longer verifies and the
	// signer does not start.
	tampered := [][]byte{
		bytes.Replace(raw, []byte(`*.example.com`), []byte(`*.example.org`), 1),
		dropLine(raw, 2),
	}
	for i, b := range tampered {
		if _, _, err := VerifyLedgerLog(bytes.NewReader(b)); err == nil {
			t.Fatalf("tampered log %d verified", i)
		}
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, LedgerLogFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(Config{Key: key, StateDir: d, Now: func() time.Time { return tNow }}); err == nil {
			t.Fatalf("signer started on tampered log %d", i)
		}
	}
}

func dropLine(raw []byte, i int) []byte {
	lines := bytes.SplitAfter(raw, []byte("\n"))
	return bytes.Join(append(lines[:i-1:i-1], lines[i:]...), nil)
}

func TestLedger_DefaultModes(t *testing.T) {
	// A signer that never signed starts in enforce mode.
	s := newService(t, t.TempDir(), newKey(t), func(c *Config) { c.LedgerMode = "" })
	if m := s.Ledger().Mode(); m != jobsign.LedgerEnforce {
		t.Fatalf("new install: %s", m)
	}

	// A signer upgraded to the ledger (it has signed before) audits: it
	// signs and records what enforce would refuse.
	dir := t.TempDir()
	key := newKey(t)
	old := newService(t, dir, key, nil)
	if _, ref := old.Sign(statement(nil)); ref != nil {
		t.Fatal(ref)
	}
	_ = old.Close()
	if err := os.Remove(filepath.Join(dir, LedgerLogFile)); err != nil { // as before the upgrade
		t.Fatal(err)
	}
	up := newService(t, dir, key, func(c *Config) { c.LedgerMode = "" })
	if m := up.Ledger().Mode(); m != jobsign.LedgerAudit {
		t.Fatalf("upgrade: %s", m)
	}
	_, ref := up.Sign(statement(func(m map[string]any) {
		m["command_id"] = "33333333-3333-4333-8333-333333333334"
		m["targets"] = []string{"victim.example.org"}
	}))
	if ref != nil {
		t.Fatalf("audit mode refused: %+v", ref)
	}
	_ = up.Close()
	logRaw, _ := os.ReadFile(filepath.Join(dir, "signing.log"))
	if !bytes.Contains(logRaw, []byte(`"ledger_audit":"out_of_ledger"`)) {
		t.Fatalf("audit not recorded:\n%s", logRaw)
	}

	// The recorded default holds across restarts; SIGNER_LEDGER overrides it.
	again := newService(t, dir, key, func(c *Config) { c.LedgerMode = "" })
	if m := again.Ledger().Mode(); m != jobsign.LedgerAudit {
		t.Fatalf("restart: %s", m)
	}
	_ = again.Close()
	if _, err := New(Config{Key: key, StateDir: dir, LedgerMode: "lenient"}); err == nil {
		t.Fatal("an unknown SIGNER_LEDGER was accepted")
	}

	// Off: nothing is checked and nothing recorded.
	off := newService(t, t.TempDir(), newKey(t), nil)
	if res, ref := off.Ledger().Apply(change(2, nil, putEntry(entry(tEntry, "domain", "*.example.com", 1, nil))), tNow); ref != nil || res.Mode != jobsign.LedgerOff {
		t.Fatalf("off apply %+v %+v", res, ref)
	}
}

func TestLedger_ImportCeremony(t *testing.T) {
	dir := t.TempDir()
	key := newKey(t)
	snap := jobsign.LedgerExport{Kind: jobsign.SnapshotKind, CreatedAt: tNow, Tenants: []jobsign.LedgerSnapshot{{
		TenantID:   tTenant,
		Entries:    []jobsign.LedgerEntry{*entry(tEntry, "domain", "*.example.com", 1, nil)},
		Exclusions: []jobsign.LedgerExclusion{{ID: tExclusion, Type: "domain", Pattern: "prod.example.com"}},
	}}}
	raw, _ := json.Marshal(snap)

	// While the signer runs it holds the lock: no import.
	running := newService(t, dir, key, func(c *Config) { c.LedgerMode = "" })
	if _, err := ImportLedger(dir, raw, false, tNow); err == nil {
		t.Fatal("imported while the signer was running")
	}
	_ = running.Close()

	res, err := ImportLedger(dir, raw, false, tNow)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tenants != 1 || res.Entries != 1 || res.Exclusions != 1 || !jobsign.ValidDigest(res.SnapshotSHA256) {
		t.Fatalf("import %+v", res)
	}
	// A second import would replace (and could widen) the ledger: only with
	// the operator's explicit -replace.
	if _, err := ImportLedger(dir, raw, false, tNow); !errors.Is(err, ErrLedgerNotEmpty) {
		t.Fatalf("second import: %v", err)
	}
	if _, err := ImportLedger(dir, raw, true, tNow); err != nil {
		t.Fatalf("replace: %v", err)
	}

	s := newService(t, dir, key, func(c *Config) { c.LedgerMode = "" })
	if m := s.Ledger().Mode(); m != jobsign.LedgerEnforce {
		t.Fatalf("after the bootstrap the default is %s, want enforce", m)
	}
	if ref := signTargets(s, "nuclei", "app.example.com"); ref != nil {
		t.Fatalf("imported scope refused: %+v", ref)
	}
	wantReason(t, signTargets(s, "nuclei", "prod.example.com"), ReasonTargetExcluded)

	// A malformed snapshot imports nothing.
	bad := bytes.Replace(raw, []byte(`"domain"`), []byte(`"everything"`), 1)
	if _, err := ImportLedger(t.TempDir(), bad, false, tNow); err == nil {
		t.Fatal("malformed snapshot imported")
	}
}

func serve(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
