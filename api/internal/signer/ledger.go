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
	ReasonTemplateNotInLed = jobsign.ReasonTemplateNotInLedger
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
	// templates are the approved custom template versions, by template id.
	templates map[string]jobsign.LedgerTemplate
	// ceilingsOff: the entries' max_tier is not enforced (scan approval
	// Off or On, RFC-073 §7); every entry covers every tier. The zero value
	// enforces the ceilings.
	ceilingsOff bool
}

func newTenantLedger() *tenantLedger {
	return &tenantLedger{entries: map[string]jobsign.LedgerEntry{}, exclusions: map[string]jobsign.LedgerExclusion{},
		templates: map[string]jobsign.LedgerTemplate{}}
}

func (t *tenantLedger) empty() bool {
	return len(t.entries) == 0 && len(t.exclusions) == 0 && len(t.templates) == 0 && !t.ceilingsOff
}

func (t *tenantLedger) clone() *tenantLedger {
	c := newTenantLedger()
	for k, v := range t.entries {
		c.entries[k] = v
	}
	for k, v := range t.exclusions {
		c.exclusions[k] = v
	}
	for k, v := range t.templates {
		c.templates[k] = v
	}
	c.ceilingsOff = t.ceilingsOff
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
		case jobsign.OpPutTemplate:
			t.templates[op.Template.ID] = *op.Template
		case jobsign.OpRemoveTemplate:
			delete(t.templates, op.ID)
		case jobsign.OpSetTierCeilings:
			t.ceilingsOff = !*op.TierCeilings
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
	// T2MinApprovals is SIGNER_LEDGER_T2_MIN_APPROVALS: a floor for a
	// widening that puts an intrusive (t2) entry into the ledger (0..2,
	// default 0: the organization's scan approval decides, RFC-073 §7).
	T2MinApprovals int
	Logger         *slog.Logger
}

// Ledger is the signer's scope ledger.
type Ledger struct {
	mu             sync.RWMutex
	log            *chainLog
	lock           *os.File
	tenants        map[string]*tenantLedger
	defaultMode    string
	mode           string
	minApprovals   int
	t2MinApprovals int
	logger         *slog.Logger
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
	if cfg.T2MinApprovals < 0 || cfg.T2MinApprovals > jobsign.MaxPolicyApprovals {
		return nil, fmt.Errorf("SIGNER_LEDGER_T2_MIN_APPROVALS must be 0 to %d", jobsign.MaxPolicyApprovals)
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
	l.lock, l.mode, l.minApprovals, l.t2MinApprovals, l.logger = lock, mode, cfg.MinApprovals, cfg.T2MinApprovals, cfg.Logger
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
	if len(next.entries) > jobsign.MaxLedgerEntries || len(next.exclusions) > jobsign.MaxLedgerExclusions ||
		len(next.templates) > jobsign.MaxLedgerTemplates {
		return jobsign.LedgerApplyResult{}, refuse(http.StatusRequestEntityTooLarge, ReasonLedgerTooLarge,
			"an organization's ledger holds at most %d entries, %d exclusions and %d templates",
			jobsign.MaxLedgerEntries, jobsign.MaxLedgerExclusions, jobsign.MaxLedgerTemplates)
	}
	counted := 0
	if kind == jobsign.ChangeWiden {
		var r *refusal
		if counted, r = l.checkApprovals(ch, cur, now); r != nil {
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
	l.logger.Info("ledger change applied", "kind", kind, "tenant_id", canonicalID(ch.TenantID), "change_id", canonicalID(ch.ChangeID),
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
		case jobsign.OpPutTemplate:
			old, ok := t.templates[op.Template.ID]
			var oldp *jobsign.LedgerTemplate
			if ok {
				oldp = &old
			}
			w := jobsign.TemplateWidens(oldp, *op.Template)
			changes, widens = changes || w, widens || w
		case jobsign.OpRemoveTemplate:
			_, ok := t.templates[op.ID]
			changes = changes || ok
		case jobsign.OpSetTierCeilings:
			off := !*op.TierCeilings
			changes = changes || off != t.ceilingsOff
			widens = widens || (off && !t.ceilingsOff)
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
	return a.ID == b.ID && a.SameScope(b) && a.MaxTier == b.MaxTier && sameTime(a.ExpiresAt, b.ExpiresAt)
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
// operator's floor for intrusive entries (which also applies to turning
// cur's tier ceilings off).
func (l *Ledger) checkApprovals(ch jobsign.LedgerChange, cur *tenantLedger, now time.Time) (int, *refusal) {
	need := max(ch.RequiredApprovals, l.minApprovals)
	for _, op := range ch.Ops {
		// Turning the tier ceilings off lets every entry cover intrusive
		// probes: it needs what an intrusive entry needs.
		if (op.Op == jobsign.OpPutEntry && op.Entry.MaxTier >= jobsign.TierIntrusive) ||
			(op.Op == jobsign.OpSetTierCeilings && !*op.TierCeilings && !cur.ceilingsOff) {
			need = max(need, l.t2MinApprovals)
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
	l.logger.Info("ledger narrowed by sync", "tenant_id", canonicalID(snap.TenantID), "ops", len(ops), "diverged", diverged)
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
		if !ok || !e.SameScope(old) {
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
	snapTpl := map[string]string{}
	for _, t := range snap.Templates {
		snapTpl[t.ID] = t.SHA256
		if old, ok := cur.templates[t.ID]; !ok || old.SHA256 != t.SHA256 {
			diverged++
		}
	}
	for _, id := range sortedKeys(cur.templates) {
		if d, ok := snapTpl[id]; !ok || d != cur.templates[id].SHA256 {
			ops = append(ops, jobsign.LedgerOp{Op: jobsign.OpRemoveTemplate, ID: id})
		}
	}
	switch {
	case cur.ceilingsOff && !snap.TierCeilingsOff:
		on := true
		ops = append(ops, jobsign.LedgerOp{Op: jobsign.OpSetTierCeilings, TierCeilings: &on})
	case !cur.ceilingsOff && snap.TierCeilingsOff:
		diverged++
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
	if d := t.unapprovedTemplate(st.Templates); d != "" {
		return refuse(http.StatusForbidden, ReasonTemplateNotInLed,
			"custom template %s is not a version the organization approved", clip(d, 80))
	}
	tier := int(stage.ProbeTier(st.Tool))
	for _, lim := range st.Limits {
		if !t.limitAllowed(lim, st.Targets, tier, now) {
			return refuse(http.StatusForbidden, ReasonOutOfLedger,
				"scope limit on %q (ports %q, path %q) is not within an approved entry", clip(lim.Host, 128), clip(lim.Ports, 64), clip(lim.PathPrefix, 128))
		}
	}
	limitedHosts := map[string]bool{}
	for _, lim := range st.Limits {
		limitedHosts[lim.Host] = true
	}
	for _, target := range st.Targets {
		if x := t.excludes(target, now); x != "" {
			return refuse(http.StatusForbidden, ReasonTargetExcluded, "target %q is excluded (%s)", clip(target, 128), clip(x, 128))
		}
		if tier <= jobsign.TierPassive || !scopedom.NeedsAuthority(target) {
			continue
		}
		covered, below, limited := t.covers(target, tier, now)
		switch {
		case covered && limited != nil && !scopedom.ConstrainedToolAllowed(st.Tool, limited.ports, limited.path) &&
			!limitedHosts[jobsign.LimitHost(target)]:
			// Any tool may run inside a limit the sensor enforces; without
			// limits in the statement only a tool that stays on its target.
			return refuse(http.StatusForbidden, ReasonOutOfLedger,
				"target %q is approved only for some ports or a path, and tool %q could reach others without scope limits", clip(target, 128), clip(st.Tool, maxToolLength))
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

// unapprovedTemplate returns the first digest of digests that no approved
// template version has, "" when all are approved.
func (t *tenantLedger) unapprovedTemplate(digests []string) string {
	if len(digests) == 0 {
		return ""
	}
	approved := make(map[string]bool, len(t.templates))
	for _, tpl := range t.templates {
		approved[tpl.SHA256] = true
	}
	for _, d := range digests {
		if !approved[d] {
			return d
		}
	}
	return ""
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

// ledgerLimits says which limits cover a target when only port- or
// path-limited entries do.
type ledgerLimits struct{ ports, path bool }

// covers reports whether an entry in effect covers target at tier, and
// whether one covers it only below tier. limited is nil when an entry
// without a port or path limit covers it, else the kinds of limits of the
// covering entries. Matching is the API's own (scopedom.EntryMatches): a
// port-limited entry covers only a target that names an allowed port, a
// path-limited URL entry only URLs under its path. With the tier ceilings
// off any covering entry covers the target at every tier.
func (t *tenantLedger) covers(target string, tier int, now time.Time) (covered, below bool, limited *ledgerLimits) {
	forms := scopedom.AuthorityForms(target)
	lim := &ledgerLimits{}
	for _, e := range t.entries {
		if jobsign.Expired(e.ExpiresAt, now) {
			continue
		}
		tt := scopedom.TargetType(e.Type)
		c := scopedom.Constraint{Ports: e.Ports, Protocol: e.Protocol}
		for _, f := range forms {
			if !scopedom.EntryMatches(tt, e.Pattern, c, f) {
				continue
			}
			if !t.ceilingsOff && e.MaxTier < tier {
				below = true
				continue
			}
			covered = true
			switch {
			case scopedom.URLPathLimited(tt, e.Pattern):
				lim.path = true
			case !c.IsZero():
				lim.ports = true
			default:
				return true, false, nil
			}
		}
	}
	if covered {
		return true, false, lim
	}
	return false, below, nil
}

// limitAllowed reports whether a statement limit lies within an entry in
// effect at tier that covers one of the statement's targets on the limit's
// host (an entry without a limit allows any limit: it is narrower).
func (t *tenantLedger) limitAllowed(lim jobsign.Limit, targets []string, tier int, now time.Time) bool {
	l := scopedom.EntryLimit{Ports: lim.Ports, Protocol: lim.Protocol, PathPrefix: lim.PathPrefix}
	for _, target := range targets {
		if jobsign.LimitHost(target) != lim.Host {
			continue
		}
		forms := scopedom.AuthorityForms(target)
		for _, e := range t.entries {
			if jobsign.Expired(e.ExpiresAt, now) || e.MaxTier < tier {
				continue
			}
			tt := scopedom.TargetType(e.Type)
			c := scopedom.Constraint{Ports: e.Ports, Protocol: e.Protocol}
			for _, f := range forms {
				if scopedom.EntryMatches(tt, e.Pattern, c, f) && scopedom.LimitWithin(l, tt, e.Pattern, c) {
					return true
				}
			}
		}
	}
	return false
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
	if op.Op == jobsign.OpSetTierCeilings {
		if op.TierCeilings == nil || op.Entry != nil || op.Exclusion != nil || op.Template != nil || op.ID != "" {
			return errors.New("set_tier_ceilings carries tier_ceilings only")
		}
		return nil
	}
	if op.TierCeilings != nil {
		return errors.New("only set_tier_ceilings carries tier_ceilings")
	}
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
	case jobsign.OpPutTemplate:
		if op.Template == nil || op.Entry != nil || op.Exclusion != nil || op.ID != "" {
			return errors.New("put_template carries a template only")
		}
		return validateTemplate(*op.Template)
	case jobsign.OpRemoveEntry, jobsign.OpRemoveExclusion, jobsign.OpRemoveTemplate:
		if op.Entry != nil || op.Exclusion != nil || op.Template != nil || !isUUID(op.ID) {
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
	case !canonicalConstraint(tt, e.Ports, e.Protocol):
		return errors.New("entry ports and protocol must be a canonical port limit for its type")
	}
	return nil
}

// canonicalConstraint reports whether ports and protocol are a port limit
// in the API's canonical form (a list that normalizes to itself), so the
// signer and the API read one limit the same way.
func canonicalConstraint(tt scopedom.TargetType, ports, protocol string) bool {
	if ports == "" && protocol == "" {
		return true
	}
	var list []string
	if ports != "" {
		list = []string{ports}
	}
	c, err := scopedom.NormalizeConstraint(tt, list, protocol)
	return err == nil && c.Ports == ports && c.Protocol == protocol
}

func validateTemplate(t jobsign.LedgerTemplate) error {
	switch {
	case !isUUID(t.ID):
		return errors.New("template id must be a lower-case UUID")
	case !jobsign.ValidDigest(t.SHA256):
		return errors.New("template sha256 must be sha256:<64 lower-case hex>")
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
	if len(s.Entries) > jobsign.MaxLedgerEntries || len(s.Exclusions) > jobsign.MaxLedgerExclusions ||
		len(s.Templates) > jobsign.MaxLedgerTemplates {
		return refuse(http.StatusRequestEntityTooLarge, ReasonLedgerTooLarge,
			"a snapshot holds at most %d entries, %d exclusions and %d templates",
			jobsign.MaxLedgerEntries, jobsign.MaxLedgerExclusions, jobsign.MaxLedgerTemplates)
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
	for i, t := range s.Templates {
		if err := validateTemplate(t); err != nil {
			return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "template %d: %s", i, err.Error())
		}
		if seen[t.ID] {
			return refuse(http.StatusBadRequest, ReasonLedgerMalformed, "template %d: duplicate id", i)
		}
		seen[t.ID] = true
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
