package signer

// The signer's scope ledger (RFC-040 §5.6 points 4 and 5): per
// organization, the scope entries and exclusions people approved, kept in
// the signer's own state directory and nowhere else. The signer signs a job
// only when its targets lie inside its organization's ledger at the tool's
// tier. A row written into the API's database, or an API process that asks
// for a job outside the ledger, gets a refusal.
//
// The ledger changes only through:
//
//   - apply (POST /v1/ledger/apply): one change from the API's scope
//     service. The signer classifies it itself (jobsign.EntryWidens and
//     friends); a widening needs the policy's approval count of people other
//     than the requester;
//   - sync (POST /v1/ledger/sync): the API's view of one organization. It
//     only ever narrows;
//   - import (openctem-signer ledger import, signer stopped): the operator's
//     bootstrap or restore ceremony.
//
// Every change is a line of ledger.log (hash-chained like the signing log,
// fsync'd before it takes effect); the state is the replay of that log.

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Ledger refusal reasons (sign time and ledger changes).
const (
	ReasonOutOfLedger      = jobsign.ReasonOutOfLedger
	ReasonTierExceedsLedge = jobsign.ReasonTierExceedsLedger
	ReasonTargetExcluded   = jobsign.ReasonTargetExcluded
	ReasonLedgerMalformed  = jobsign.ReasonLedgerMalformed
	ReasonLedgerTooLarge   = jobsign.ReasonLedgerTooLarge
	ReasonNotApproved      = jobsign.ReasonLedgerNotApproved
)

// Record kinds of ledger.log.
const (
	recordInit   = "init"
	recordImport = "import"
	recordSync   = "sync"
)

// LedgerRecord is one line of ledger.log.
type LedgerRecord struct {
	Time time.Time `json:"time"`
	// Kind: init, widen, narrow, sync or import. An import record without
	// a tenant starts an import: the whole ledger is replaced by the
	// import records that follow it.
	Kind              string                   `json:"kind"`
	TenantID          string                   `json:"tenant_id,omitempty"`
	ChangeID          string                   `json:"change_id,omitempty"`
	Requester         string                   `json:"requester,omitempty"`
	Approvals         []jobsign.LedgerApproval `json:"approvals,omitempty"`
	RequiredApprovals int                      `json:"policy_required_approvals,omitempty"`
	// CountedApprovals is the approvals the signer counted (widen).
	CountedApprovals int                `json:"counted_approvals,omitempty"`
	PlatformPolicy   string             `json:"platform_policy,omitempty"`
	Ops              []jobsign.LedgerOp `json:"ops,omitempty"`
	// DefaultMode (init, import start) is the mode the signer runs in when
	// SIGNER_LEDGER does not say.
	DefaultMode string `json:"default_mode,omitempty"`
	// SnapshotSHA256 (import start) is the digest of the imported file.
	SnapshotSHA256 string `json:"snapshot_sha256,omitempty"`
	Prev           string `json:"prev"`
}

// tenantLedger is one organization's ledger.
type tenantLedger struct {
	entries    map[string]jobsign.LedgerEntry
	exclusions map[string]jobsign.LedgerExclusion
}

func newTenantLedger() *tenantLedger {
	return &tenantLedger{entries: map[string]jobsign.LedgerEntry{}, exclusions: map[string]jobsign.LedgerExclusion{}}
}

func (t *tenantLedger) empty() bool { return len(t.entries) == 0 && len(t.exclusions) == 0 }

func (t *tenantLedger) clone() *tenantLedger {
	c := newTenantLedger()
	for k, v := range t.entries {
		c.entries[k] = v
	}
	for k, v := range t.exclusions {
		c.exclusions[k] = v
	}
	return c
}

// apply applies ops; an entry put already expired is removed.
func (t *tenantLedger) apply(ops []jobsign.LedgerOp, now time.Time) {
	for _, op := range ops {
		switch op.Op {
		case jobsign.OpPutEntry:
			if jobsign.Expired(op.Entry.ExpiresAt, now) {
				delete(t.entries, op.Entry.ID)
				continue
			}
			t.entries[op.Entry.ID] = *op.Entry
		case jobsign.OpRemoveEntry:
			delete(t.entries, op.ID)
		case jobsign.OpPutExclusion:
			t.exclusions[op.Exclusion.ID] = *op.Exclusion
		case jobsign.OpRemoveExclusion:
			delete(t.exclusions, op.ID)
		}
	}
}

// LedgerConfig configures OpenLedger.
type LedgerConfig struct {
	// Path is ledger.log; LockPath the lock file held while the ledger is
	// open (a second process, such as an import, cannot open it).
	Path, LockPath string
	// Fresh: the signer has never signed (its signing log is empty), so a
	// new ledger defaults to enforce; otherwise to audit (an upgrade).
	Fresh bool
	// Mode is SIGNER_LEDGER ("": the recorded default).
	Mode string
	// MinApprovals is SIGNER_LEDGER_MIN_APPROVALS: a floor under the
	// organization's approval count for every widening.
	MinApprovals int
	Logger       *slog.Logger
}

// Ledger is the signer's scope ledger.
type Ledger struct {
	mu           sync.RWMutex
	log          *chainLog
	lock         *os.File
	tenants      map[string]*tenantLedger
	defaultMode  string
	mode         string
	minApprovals int
	logger       *slog.Logger
}

// ParseLedgerMode reads SIGNER_LEDGER ("" is allowed: the default).
func ParseLedgerMode(s string) (string, error) {
	switch s {
	case "", jobsign.LedgerEnforce, jobsign.LedgerAudit, jobsign.LedgerOff:
		return s, nil
	}
	return "", fmt.Errorf("SIGNER_LEDGER must be enforce, audit or off, not %q", s)
}

// OpenLedger takes the ledger lock, verifies ledger.log and replays it. A
// new ledger gets its init record (default mode from cfg.Fresh).
func OpenLedger(cfg LedgerConfig, now time.Time) (*Ledger, error) {
	mode, err := ParseLedgerMode(cfg.Mode)
	if err != nil {
		return nil, err
	}
	if cfg.MinApprovals < 0 || cfg.MinApprovals > jobsign.MaxPolicyApprovals {
		return nil, fmt.Errorf("SIGNER_LEDGER_MIN_APPROVALS must be 0 to %d", jobsign.MaxPolicyApprovals)
	}
	lock, err := lockFile(cfg.LockPath)
	if err != nil {
		return nil, err
	}
	l, err := openLedgerLocked(cfg.Path, cfg.Fresh, now)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	l.lock, l.mode, l.minApprovals, l.logger = lock, mode, cfg.MinApprovals, cfg.Logger
	if l.logger == nil {
		l.logger = slog.New(slog.DiscardHandler)
	}
	return l, nil
}

func openLedgerLocked(path string, fresh bool, now time.Time) (*Ledger, error) {
	l := &Ledger{tenants: map[string]*tenantLedger{}}
	cl, err := openChainLog(path, "ledger", maxLedgerLine, func(line []byte) error {
		var r LedgerRecord
		if err := strictUnmarshal(line, &r); err != nil {
			return err
		}
		return l.replay(r)
	})
	if err != nil {
		return nil, err
	}
	l.log = cl
	if cl.entries == 0 {
		def := jobsign.LedgerAudit
		if fresh {
			def = jobsign.LedgerEnforce
		}
		if err := cl.append(&LedgerRecord{Time: now.UTC(), Kind: recordInit, DefaultMode: def}); err != nil {
			_ = cl.close()
			return nil, err
		}
		l.defaultMode = def
	}
	return l, nil
}

// replay applies one record read back from the log.
func (l *Ledger) replay(r LedgerRecord) error {
	switch r.Kind {
	case recordInit:
		l.defaultMode = r.DefaultMode
	case recordImport:
		if r.TenantID == "" {
			l.tenants = map[string]*tenantLedger{}
			l.defaultMode = r.DefaultMode
			return nil
		}
		t := newTenantLedger()
		t.apply(r.Ops, r.Time)
		l.tenants[r.TenantID] = t
	case jobsign.ChangeWiden, jobsign.ChangeNarrow, recordSync:
		l.tenant(r.TenantID).apply(r.Ops, r.Time)
	default:
		return fmt.Errorf("unknown ledger record kind %q", r.Kind)
	}
	return nil
}

func (l *Ledger) tenant(id string) *tenantLedger {
	t := l.tenants[id]
	if t == nil {
		t = newTenantLedger()
		l.tenants[id] = t
	}
	return t
}

// Close closes the log and releases the lock.
func (l *Ledger) Close() error {
	err := l.log.close()
	if l.lock != nil {
		_ = l.lock.Close()
	}
	return err
}

// Mode is the mode in force: SIGNER_LEDGER, else the recorded default.
func (l *Ledger) Mode() string {
	if l.mode != "" {
		return l.mode
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.defaultMode
}

// Status lists the organizations with anything in the ledger.
func (l *Ledger) Status() jobsign.LedgerStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := jobsign.LedgerStatus{Tenants: []string{}}
	for id, t := range l.tenants {
		if !t.empty() {
			out.Tenants = append(out.Tenants, id)
		}
	}
	sort.Strings(out.Tenants)
	out.Mode = l.modeLocked()
	return out
}

func (l *Ledger) modeLocked() string {
	if l.mode != "" {
		return l.mode
	}
	return l.defaultMode
}

// Apply validates, classifies and records one change. In off mode nothing
// is recorded.
func (l *Ledger) Apply(ch jobsign.LedgerChange, now time.Time) (jobsign.LedgerApplyResult, *refusal) {
	l.mu.Lock()
	defer l.mu.Unlock()
	mode := l.modeLocked()
	if mode == jobsign.LedgerOff {
		return jobsign.LedgerApplyResult{Kind: jobsign.ChangeNoop, Mode: mode}, nil
	}
	if r := validateChange(ch); r != nil {
		return jobsign.LedgerApplyResult{}, r
	}
	cur := l.tenants[ch.TenantID]
	if cur == nil {
		cur = newTenantLedger()
	}
	kind := classify(cur, ch.Ops, now)
	if kind == jobsign.ChangeNoop {
		return jobsign.LedgerApplyResult{Kind: kind, Mode: mode}, nil
	}
	next := cur.clone()
	next.apply(ch.Ops, now)
	if len(next.entries) > jobsign.MaxLedgerEntries || len(next.exclusions) > jobsign.MaxLedgerExclusions {
		return jobsign.LedgerApplyResult{}, refuse(http.StatusRequestEntityTooLarge, ReasonLedgerTooLarge,
			"an organization's ledger holds at most %d entries and %d exclusions", jobsign.MaxLedgerEntries, jobsign.MaxLedgerExclusions)
	}
	counted := 0
	if kind == jobsign.ChangeWiden {
		var r *refusal
		if counted, r = l.checkApprovals(ch, now); r != nil {
			return jobsign.LedgerApplyResult{}, r
		}
	}
	rec := &LedgerRecord{
		Time: now.UTC(), Kind: kind, TenantID: ch.TenantID, ChangeID: ch.ChangeID, Requester: ch.Requester,
		Approvals: ch.Approvals, RequiredApprovals: ch.RequiredApprovals, CountedApprovals: counted,
		PlatformPolicy: ch.PlatformPolicy, Ops: ch.Ops,
	}
	if err := l.log.append(rec); err != nil {
		l.logger.Error("ledger log not written; change not applied", "error", oneLine(err.Error()))
		return jobsign.LedgerApplyResult{}, refuse(http.StatusInternalServerError, ReasonInternal, "ledger log unavailable")
	}
	l.tenants[ch.TenantID] = next
	l.logger.Info("ledger change applied", "kind", kind, "tenant_id", ch.TenantID, "change_id", ch.ChangeID,
		"ops", len(ch.Ops), "approvals", counted)
	return jobsign.LedgerApplyResult{Kind: kind, Mode: mode}, nil
}

// classify is the change's kind against cur: widen when any operation
// widens (applied in order), noop when nothing changes, else narrow.
func classify(cur *tenantLedger, ops []jobsign.LedgerOp, now time.Time) string {
	t := cur.clone()
	widens, changes := false, false
	for _, op := range ops {
		switch op.Op {
		case jobsign.OpPutEntry:
			old, ok := t.entries[op.Entry.ID]
			var oldp *jobsign.LedgerEntry
			if ok {
				oldp = &old
			}
			if jobsign.Expired(op.Entry.ExpiresAt, now) {
				changes = changes || ok
			} else {
				changes = changes || !ok || !sameEntry(old, *op.Entry)
				widens = widens || jobsign.EntryWidens(oldp, *op.Entry, now)
			}
		case jobsign.OpRemoveEntry:
			_, ok := t.entries[op.ID]
			changes = changes || ok
		case jobsign.OpPutExclusion:
			old, ok := t.exclusions[op.Exclusion.ID]
			var oldp *jobsign.LedgerExclusion
			if ok {
				oldp = &old
			}
			changes = changes || !ok || !sameExclusion(old, *op.Exclusion)
			widens = widens || jobsign.ExclusionPutWidens(oldp, *op.Exclusion, now)
		case jobsign.OpRemoveExclusion:
			old, ok := t.exclusions[op.ID]
			changes = changes || ok
			if ok {
				widens = widens || jobsign.ExclusionRemoveWidens(&old, now)
			}
		}
		t.apply([]jobsign.LedgerOp{op}, now)
	}
	switch {
	case widens:
		return jobsign.ChangeWiden
	case changes:
		return jobsign.ChangeNarrow
	}
	return jobsign.ChangeNoop
}

func sameEntry(a, b jobsign.LedgerEntry) bool {
	return a.ID == b.ID && a.Type == b.Type && a.Pattern == b.Pattern && a.MaxTier == b.MaxTier && sameTime(a.ExpiresAt, b.ExpiresAt)
}

func sameExclusion(a, b jobsign.LedgerExclusion) bool {
	return a.ID == b.ID && a.Type == b.Type && a.Pattern == b.Pattern && sameTime(a.ExpiresAt, b.ExpiresAt)
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// checkApprovals counts the distinct approvers of a widening who are not
// the requester (a self-approval under RFC-054 §12 A2 counts once) and
// compares them with the policy's count, the operator's floor and the
// intrusive minimum of one.
func (l *Ledger) checkApprovals(ch jobsign.LedgerChange, now time.Time) (int, *refusal) {
	need := max(ch.RequiredApprovals, l.minApprovals)
	for _, op := range ch.Ops {
		if op.Op == jobsign.OpPutEntry && op.Entry.MaxTier >= jobsign.TierIntrusive {
			need = max(need, 1)
		}
	}
	seen := map[string]bool{}
	counted, self := 0, false
	for i, a := range ch.Approvals {
		switch {
		case !isUUID(a.UserID):
			return 0, refuse(http.StatusBadRequest, ReasonLedgerMalformed, "approval %d: user_id must be a lower-case UUID", i)
		case a.ApprovedAt.IsZero() || a.ApprovedAt.After(now.Add(jobsign.MaxClockSkew)):
			return 0, refuse(http.StatusBadRequest, ReasonLedgerMalformed, "approval %d: approved_at is missing or in the future", i)
		case seen[a.UserID]:
			return 0, refuse(http.StatusBadRequest, ReasonLedgerMalformed, "approval %d: the same person approved twice", i)
		case a.SelfApproved && a.UserID != ch.Requester:
			return 0, refuse(http.StatusBadRequest, ReasonLedgerMalformed, "approval %d: a self-approval must be the requester's", i)
		}
		seen[a.UserID] = true
		switch {
		case a.UserID != ch.Requester:
			counted++
		case a.SelfApproved && !self:
			self = true
			counted++
		}
	}
	if counted < need {
		return 0, refuse(http.StatusForbidden, ReasonNotApproved,
			"this widening needs %d approval(s) by people other than the requester; %d counted", need, counted)
	}
	return counted, nil
}

// Sync narrows one organization's ledger to the API's snapshot: entries
// the snapshot no longer holds are removed, entries it holds narrower are
// narrowed (lower tier, earlier expiry), exclusions it holds that the
// ledger lacks are added and the ledger's exclusions are kept at the later
// of the two expiries. Nothing the snapshot holds wider is taken: it is
// counted as diverged.
func (l *Ledger) Sync(snap jobsign.LedgerSnapshot, now time.Time) (jobsign.LedgerSyncResult, *refusal) {
	l.mu.Lock()
	defer l.mu.Unlock()
	mode := l.modeLocked()
	if mode == jobsign.LedgerOff {
		return jobsign.LedgerSyncResult{Mode: mode}, nil
	}
	if r := validateSnapshot(snap); r != nil {
		return jobsign.LedgerSyncResult{}, r
	}
	cur := l.tenants[snap.TenantID]
	if cur == nil {
		cur = newTenantLedger()
	}
	ops, diverged := narrowingOps(cur, snap, now)
	res := jobsign.LedgerSyncResult{Mode: mode, Narrowed: len(ops), Diverged: diverged}
	if len(ops) == 0 {
		return res, nil
	}
	if err := l.log.append(&LedgerRecord{Time: now.UTC(), Kind: recordSync, TenantID: snap.TenantID, Ops: ops}); err != nil {
		l.logger.Error("ledger log not written; sync not applied", "error", oneLine(err.Error()))
		return jobsign.LedgerSyncResult{}, refuse(http.StatusInternalServerError, ReasonInternal, "ledger log unavailable")
	}
	cur = cur.clone()
	cur.apply(ops, now)
	l.tenants[snap.TenantID] = cur
	l.logger.Info("ledger narrowed by sync", "tenant_id", snap.TenantID, "ops", len(ops), "diverged", diverged)
	return res, nil
}

// narrowingOps are the operations that narrow cur toward snap, and the
// number of snapshot items wider than the ledger.
func narrowingOps(cur *tenantLedger, snap jobsign.LedgerSnapshot, now time.Time) ([]jobsign.LedgerOp, int) {
	var ops []jobsign.LedgerOp
	diverged := 0
	inSnap := map[string]jobsign.LedgerEntry{}
	for _, e := range snap.Entries {
		inSnap[e.ID] = e
	}
	for _, id := range sortedKeys(cur.entries) {
		old := cur.entries[id]
		e, ok := inSnap[id]
		if !ok || e.Type != old.Type || e.Pattern != old.Pattern {
			ops = append(ops, jobsign.LedgerOp{Op: jobsign.OpRemoveEntry, ID: id})
			continue
		}
		n := old
		n.MaxTier = min(old.MaxTier, e.MaxTier)
		n.ExpiresAt = earlier(old.ExpiresAt, e.ExpiresAt)
		if !sameEntry(n, old) {
			ops = append(ops, jobsign.LedgerOp{Op: jobsign.OpPutEntry, Entry: &n})
		}
		if !sameEntry(n, e) {
			diverged++
		}
	}
	for _, e := range snap.Entries {
		if _, ok := cur.entries[e.ID]; !ok && !jobsign.Expired(e.ExpiresAt, now) {
			diverged++
		}
	}
	snapEx := map[string]bool{}
	for _, x := range snap.Exclusions {
		snapEx[x.ID] = true
		old, ok := cur.exclusions[x.ID]
		if !ok {
			x := x
			ops = append(ops, jobsign.LedgerOp{Op: jobsign.OpPutExclusion, Exclusion: &x})
			continue
		}
		if old.Type != x.Type || old.Pattern != x.Pattern {
			diverged++
			continue
		}
		if laterEnds(old.ExpiresAt, x.ExpiresAt) {
			n := old
			n.ExpiresAt = x.ExpiresAt
			ops = append(ops, jobsign.LedgerOp{Op: jobsign.OpPutExclusion, Exclusion: &n})
		} else if !sameTime(old.ExpiresAt, x.ExpiresAt) {
			diverged++
		}
	}
	for id, x := range cur.exclusions {
		if !snapEx[id] && !jobsign.Expired(x.ExpiresAt, now) {
			diverged++
		}
	}
	return ops, diverged
}

// earlier is the earlier of two expiries (nil: never).
func earlier(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.Before(*a):
		return b
	}
	return a
}

// laterEnds reports whether next ends later than prev (nil: never).
func laterEnds(prev, next *time.Time) bool {
	switch {
	case prev == nil:
		return false
	case next == nil:
		return true
	}
	return next.After(*prev)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Check is the sign-time check of st against its organization's ledger:
// nil when every target may be probed at the tool's tier. Exclusions apply
// to every target; passive (T0) tools and targets the API gates by zones
// (internal names and private addresses, scopedom.NeedsAuthority) need no
// entry, as in the API's authority check (RFC-054 §4.2).
func (l *Ledger) Check(st *jobsign.Statement, now time.Time) *refusal {
	l.mu.RLock()
	defer l.mu.RUnlock()
	t := l.tenants[st.TenantID]
	if t == nil {
		t = newTenantLedger()
	}
	tier := int(stage.ProbeTier(st.Tool))
	for _, target := range st.Targets {
		if x := t.excludes(target, now); x != "" {
			return refuse(http.StatusForbidden, ReasonTargetExcluded, "target %q is excluded (%s)", clip(target, 128), clip(x, 128))
		}
		if tier <= jobsign.TierPassive || !scopedom.NeedsAuthority(target) {
			continue
		}
		covered, below := t.covers(target, tier, now)
		switch {
		case covered:
		case below:
			return refuse(http.StatusForbidden, ReasonTierExceedsLedge,
				"target %q is approved below tier t%d (tool %q)", clip(target, 128), tier, clip(st.Tool, maxToolLength))
		default:
			return refuse(http.StatusForbidden, ReasonOutOfLedger,
				"target %q is outside the organization's approved scope", clip(target, 128))
		}
	}
	return nil
}

// excludes returns the pattern of an exclusion in effect matching target.
func (t *tenantLedger) excludes(target string, now time.Time) string {
	forms := scopedom.ExclusionForms(target)
	for _, x := range t.exclusions {
		if jobsign.Expired(x.ExpiresAt, now) {
			continue
		}
		for _, f := range forms {
			if scopedom.MatchesExclusionPattern(scopedom.ExclusionType(x.Type), x.Pattern, f) {
				return x.Pattern
			}
		}
	}
	return ""
}

// covers reports whether an entry in effect covers target at tier, and
// whether one covers it only below tier.
func (t *tenantLedger) covers(target string, tier int, now time.Time) (covered, below bool) {
	forms := scopedom.AuthorityForms(target)
	for _, e := range t.entries {
		if jobsign.Expired(e.ExpiresAt, now) {
			continue
		}
		for _, f := range forms {
			if !scopedom.MatchesPattern(scopedom.TargetType(e.Type), e.Pattern, f) {
				continue
			}
			if e.MaxTier >= tier {
				return true, false
			}
			below = true
		}
	}
	return false, below
}

// ledgerExclusionTypes are the exclusion types that name targets.
var ledgerExclusionTypes = map[string]bool{
	string(scopedom.ExclusionTypeDomain): true, string(scopedom.ExclusionTypeSubdomain): true,
	string(scopedom.ExclusionTypeIPAddress): true, string(scopedom.ExclusionTypeIPRange): true,
	string(scopedom.ExclusionTypeCIDR): true, string(scopedom.ExclusionTypeURL): true,
	string(scopedom.ExclusionTypeRepository): true,
}

// LedgerExclusionType reports whether an exclusion of type t belongs in the
// ledger.
func LedgerExclusionType(t string) bool { return ledgerExclusionTypes[t] }

func validateChange(ch jobsign.LedgerChange) *refusal {
	switch {
	case !isUUID(ch.TenantID):
		return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "tenant_id must be a lower-case UUID")
	case !isUUID(ch.ChangeID):
		return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "change_id must be a lower-case UUID")
	case ch.Requester != "" && !isUUID(ch.Requester):
		return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "requester must be empty or a lower-case UUID")
	case ch.RequiredApprovals < 0 || ch.RequiredApprovals > jobsign.MaxPolicyApprovals:
		return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "policy_required_approvals must be 0 to %d", jobsign.MaxPolicyApprovals)
	case len(ch.Approvals) > jobsign.MaxLedgerApprovals:
		return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "more than %d approvals", jobsign.MaxLedgerApprovals)
	case len(ch.PlatformPolicy) > jobsign.MaxPlatformPolicyBytes || strings.ContainsAny(ch.PlatformPolicy, "\r\n"):
		return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "platform_policy is too long or not one line")
	case len(ch.Ops) == 0 || len(ch.Ops) > jobsign.MaxLedgerOps:
		return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "a change has 1 to %d operations", jobsign.MaxLedgerOps)
	}
	for i, op := range ch.Ops {
		if err := validateOp(op); err != nil {
			return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "operation %d: %s", i, err.Error())
		}
	}
	return nil
}

func validateOp(op jobsign.LedgerOp) error {
	switch op.Op {
	case jobsign.OpPutEntry:
		if op.Entry == nil || op.Exclusion != nil || op.ID != "" {
			return errors.New("put_entry carries an entry only")
		}
		return validateEntry(*op.Entry)
	case jobsign.OpPutExclusion:
		if op.Exclusion == nil || op.Entry != nil || op.ID != "" {
			return errors.New("put_exclusion carries an exclusion only")
		}
		return validateExclusion(*op.Exclusion)
	case jobsign.OpRemoveEntry, jobsign.OpRemoveExclusion:
		if op.Entry != nil || op.Exclusion != nil || !isUUID(op.ID) {
			return errors.New("a remove operation carries a lower-case UUID id only")
		}
		return nil
	}
	return fmt.Errorf("unknown operation %q", clip(op.Op, 32))
}

func validateEntry(e jobsign.LedgerEntry) error {
	tt, err := scopedom.ParseTargetType(e.Type)
	switch {
	case !isUUID(e.ID):
		return errors.New("entry id must be a lower-case UUID")
	case err != nil || string(tt) != e.Type:
		return errors.New("entry type is not a scope target type")
	case e.Pattern == "" || len(e.Pattern) > jobsign.MaxLedgerPatternBytes || strings.ContainsAny(e.Pattern, "\r\n"):
		return fmt.Errorf("entry pattern must be 1 to %d bytes on one line", jobsign.MaxLedgerPatternBytes)
	case scopedom.ValidatePattern(tt, e.Pattern) != nil:
		return errors.New("entry pattern is not valid for its type")
	case e.MaxTier < jobsign.TierPassive || e.MaxTier > jobsign.TierIntrusive:
		return errors.New("entry max_tier must be 0, 1 or 2")
	case e.MaxTier == jobsign.TierIntrusive && e.ExpiresAt == nil:
		return errors.New("an intrusive (t2) entry needs an expiry")
	}
	return nil
}

func validateExclusion(x jobsign.LedgerExclusion) error {
	switch {
	case !isUUID(x.ID):
		return errors.New("exclusion id must be a lower-case UUID")
	case !LedgerExclusionType(x.Type):
		return errors.New("exclusion type does not name targets")
	case x.Pattern == "" || len(x.Pattern) > jobsign.MaxLedgerPatternBytes || strings.ContainsAny(x.Pattern, "\r\n"):
		return fmt.Errorf("exclusion pattern must be 1 to %d bytes on one line", jobsign.MaxLedgerPatternBytes)
	}
	return nil
}

func validateSnapshot(s jobsign.LedgerSnapshot) *refusal {
	if !isUUID(s.TenantID) {
		return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "tenant_id must be a lower-case UUID")
	}
	if len(s.Entries) > jobsign.MaxLedgerEntries || len(s.Exclusions) > jobsign.MaxLedgerExclusions {
		return refuse(http.StatusRequestEntityTooLarge, ReasonLedgerTooLarge,
			"a snapshot holds at most %d entries and %d exclusions", jobsign.MaxLedgerEntries, jobsign.MaxLedgerExclusions)
	}
	seen := map[string]bool{}
	for i, e := range s.Entries {
		if err := validateEntry(e); err != nil {
			return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "entry %d: %s", i, err.Error())
		}
		if seen[e.ID] {
			return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "entry %d: duplicate id", i)
		}
		seen[e.ID] = true
	}
	for i, x := range s.Exclusions {
		if err := validateExclusion(x); err != nil {
			return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "exclusion %d: %s", i, err.Error())
		}
		if seen[x.ID] {
			return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "exclusion %d: duplicate id", i)
		}
		seen[x.ID] = true
	}
	return nil
}

// lockFile creates (0600) and locks path exclusively without waiting.
func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- the signer's own state file
	if err != nil {
		return nil, fmt.Errorf("ledger lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- a file descriptor fits an int
		_ = f.Close()
		return nil, fmt.Errorf("ledger lock: another process holds the ledger (stop the signer first): %w", err)
	}
	return f, nil
}
