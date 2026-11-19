// Package threatalert plans and delivers emerging-threat alerts: one per
// organization and vulnerability, opened or escalated by material
// vulnerability events and by findings the matcher creates, scored, routed
// to an immediate message, the daily digest or the list, under a per-hour
// cap and quiet hours.
//
// Threat model: the planner runs as the system and reads every
// organization's affected assets to decide; nothing it reads leaves the
// organization it belongs to. Every write carries the organization. Channel
// messages hold vulnerability ids, catalog product names (stripped of
// markup) and host counts; asset names only when the organization turns them on
// (at most five). The rate cap and the levels bound what a poisoned feed can
// cause. E-mail digests are counted within each recipient's data scope.
//
// Design: docs/rfcs/RFC-117-emerging-threat-alerts.md.
package threatalert

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/internal/app/outbox"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
	"github.com/openctemio/openctem/server/pkg/domain/vulnevent"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Windows and limits.
const (
	// EventWindow: a vulnerability with a material event this recent opens
	// alerts.
	EventWindow = 30 * 24 * time.Hour
	// KEVWindow: a KEV addition this recent opens alerts.
	KEVWindow = 90 * 24 * time.Hour
	// MaxImmediatePerHour caps the immediate messages per organization.
	MaxImmediatePerHour = 5
	// gapWait is how long a gap in event ids is waited for (a transaction
	// that took an id may not have committed yet).
	gapWait   = 2 * time.Minute
	eventPage = 500
	queuePage = 200
	// baselinePerRun bounds the organizations baselined in one run.
	baselinePerRun = 10
	pendingSweep   = 200
	moduleID       = "threat_intel"
)

// TenantReader loads an organization (its settings).
type TenantReader interface {
	GetByID(ctx context.Context, id shared.ID) (*tenant.Tenant, error)
}

// ModuleChecker reports whether a module is on for an organization.
type ModuleChecker interface {
	IsEnabled(ctx context.Context, tenantID, moduleID string) bool
}

// Enqueuer is the notification outbox.
type Enqueuer interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// InAppNotifier creates in-app notifications.
type InAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// AdminDirectory lists an organization's active administrators.
type AdminDirectory interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// ScopeResolver resolves a member's data scope outside a request.
type ScopeResolver interface {
	ForUser(ctx context.Context, tenantID, userID shared.ID) (*shared.DataScope, error)
}

// Mailer sends the e-mail digest through the organization's (or the
// system's) mail settings.
type Mailer interface {
	SendEmergingThreatMail(ctx context.Context, tenantID string, to []string, subject, htmlBody string)
}

// Planner plans and delivers alerts.
type Planner struct {
	store   threatalert.PlannerStore
	tenants TenantReader
	modules ModuleChecker
	outbox  Enqueuer
	inApp   InAppNotifier
	admins  AdminDirectory
	scopes  ScopeResolver
	mail    Mailer
	webBase string
	logger  *logger.Logger
	now     func() time.Time
}

// NewPlanner creates a planner. The sinks are optional (nil: skipped).
func NewPlanner(store threatalert.PlannerStore, tenants TenantReader, log *logger.Logger) *Planner {
	return &Planner{store: store, tenants: tenants, logger: log.With("service", "threat_alerts"), now: time.Now}
}

// SetSinks wires the delivery sinks and the console base URL (links in
// e-mails).
func (p *Planner) SetSinks(o Enqueuer, inApp InAppNotifier, admins AdminDirectory, scopes ScopeResolver, mail Mailer, webBase string) {
	p.outbox, p.inApp, p.admins, p.scopes, p.mail, p.webBase = o, inApp, admins, scopes, mail, webBase
}

// SetModules wires the module check (nil: every organization has it).
func (p *Planner) SetModules(m ModuleChecker) { p.modules = m }

// SetClockForTest replaces the clock.
func SetClockForTest(p *Planner, now func() time.Time) { p.now = now }

// Stats says what a run did.
type Stats struct {
	Events    int
	Planned   int
	Baselined int
	Immediate int
	Digests   int
}

// policy is one organization's effective settings for this run.
type policy struct {
	active   bool
	settings tenant.EmergingThreatSettings
	vm       tenant.VulnMatchingSettings
	loc      *time.Location
}

type runState struct {
	policies map[shared.ID]*policy
	touched  map[shared.ID]bool
}

func (p *Planner) policyOf(ctx context.Context, rs *runState, tenantID shared.ID) *policy {
	if pol, ok := rs.policies[tenantID]; ok {
		return pol
	}
	pol := &policy{loc: time.UTC}
	t, err := p.tenants.GetByID(ctx, tenantID)
	if err == nil && t != nil {
		s := t.TypedSettings()
		pol.settings = s.EmergingThreats.Effective()
		pol.vm = s.VulnMatching
		if loc, lerr := time.LoadLocation(s.General.Timezone); lerr == nil && s.General.Timezone != "" {
			pol.loc = loc
		}
		pol.active = !pol.settings.Disabled && (p.modules == nil || p.modules.IsEnabled(ctx, tenantID.String(), moduleID))
	}
	rs.policies[tenantID] = pol
	return pol
}

// Run does one pass within budget: fan events out to the organizations they
// affect, baseline new organizations, plan the queue, send pending
// immediate alerts and the digests that are due.
func (p *Planner) Run(ctx context.Context, budget time.Duration) (Stats, error) {
	var st Stats
	deadline := p.now().Add(budget)
	rs := &runState{policies: map[shared.ID]*policy{}, touched: map[shared.ID]bool{}}
	if err := p.fanOut(ctx, &st, deadline); err != nil {
		return st, err
	}
	if err := p.baselines(ctx, rs, &st, deadline); err != nil {
		return st, err
	}
	// Items that failed to plan go back to the queue after this loop (not
	// inside it: a persistent failure would spin until the deadline).
	var retry []threatalert.QueueItem
	defer func() {
		if len(retry) > 0 {
			if err := p.store.Enqueue(ctx, retry); err != nil {
				p.logger.Warn("emerging threats not re-queued", "items", len(retry), "error", err)
			}
		}
	}()
	for p.now().Before(deadline) {
		items, err := p.store.Dequeue(ctx, queuePage)
		if err != nil {
			return st, err
		}
		if len(items) == 0 {
			break
		}
		for i, it := range items {
			if !p.now().Before(deadline) {
				if err := p.store.Enqueue(ctx, items[i:]); err != nil {
					return st, err
				}
				break
			}
			if err := p.plan(ctx, rs, it.TenantID, it.VulnID, false); err != nil {
				p.logger.Warn("emerging threat not planned", "tenant_id", it.TenantID.String(), "vuln_id", it.VulnID, "error", err)
				retry = append(retry, it)
				continue
			}
			st.Planned++
		}
	}
	pending, err := p.store.TenantsWithPendingImmediate(ctx, pendingSweep)
	if err != nil {
		return st, err
	}
	for _, id := range pending {
		rs.touched[id] = true
	}
	for id := range rs.touched {
		n, err := p.flush(ctx, rs, id)
		if err != nil {
			p.logger.Warn("emerging threats not sent", "tenant_id", id.String(), "error", err)
		}
		st.Immediate += n
	}
	n, err := p.digests(ctx, rs)
	st.Digests = n
	return st, err
}

// fanOut reads the events after the cursor and queues every organization
// each one affects. A rejection resolves the vulnerability's alerts.
func (p *Planner) fanOut(ctx context.Context, st *Stats, deadline time.Time) error {
	cursor, err := p.store.PlannerCursor(ctx)
	if err != nil {
		return err
	}
	for p.now().Before(deadline) {
		events, err := p.store.EventsAfter(ctx, cursor, eventPage)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return nil
		}
		// The page up to the first gap in event ids: an earlier id may
		// still commit, so the events after it wait for the next run.
		ready, next := len(events), cursor
		for i, e := range events {
			if e.ID != next+1 && p.now().Sub(e.At) < gapWait {
				ready = i
				break
			}
			next = e.ID
		}
		if err := p.fanOutPage(ctx, events[:ready]); err != nil {
			_ = p.store.SetPlannerCursor(ctx, cursor)
			return err
		}
		st.Events += ready
		if ready > 0 {
			cursor = events[ready-1].ID
		}
		if err := p.store.SetPlannerCursor(ctx, cursor); err != nil {
			return err
		}
		if ready < len(events) {
			return nil
		}
	}
	return nil
}

// fanOutPage queues the organizations a page of events affects, with one
// lookup for the whole page. Rejections resolve in event order, after the
// events before them are queued (queueing is idempotent, so a page that
// fails half way is safely redone from the old cursor).
func (p *Planner) fanOutPage(ctx context.Context, events []vulnevent.Event) error {
	var ids []string
	for _, e := range events {
		if e.Kind != vulnevent.KindRejected && e.Kind != vulnevent.KindCardWithdrawn {
			ids = append(ids, e.VulnID)
		}
	}
	affected, err := p.store.TenantsAffectedBy(ctx, ids)
	if err != nil {
		return err
	}
	// A vulnerability a reviewed advisory card groups is planned as the
	// card: one alert per organization and card.
	groups, err := p.store.CardsGrouping(ctx, ids)
	if err != nil {
		return err
	}
	var items []threatalert.QueueItem
	queued := map[threatalert.QueueItem]bool{}
	flush := func() error {
		if len(items) == 0 {
			return nil
		}
		err := p.store.Enqueue(ctx, items)
		items = nil
		return err
	}
	for _, e := range events {
		if e.Kind == vulnevent.KindRejected {
			if err := flush(); err != nil {
				return err
			}
			n, err := p.store.ResolveVuln(ctx, e.VulnID, threatalert.ReasonRejectedUpstream, p.now())
			if err != nil {
				return err
			}
			if n > 0 {
				p.logger.Info("emerging threats resolved: CVE rejected upstream", "vuln_id", e.VulnID, "alerts", n)
			}
			continue
		}
		if e.Kind == vulnevent.KindCardWithdrawn {
			if err := p.cardWithdrawn(ctx, e.VulnID, flush); err != nil {
				return err
			}
			continue
		}
		if e.Kind == vulnevent.KindCardUpdated {
			if err := p.cardUpdated(ctx, e.VulnID, flush); err != nil {
				return err
			}
		}
		key := e.VulnID
		if card := groups[key]; card != "" {
			key = card
		}
		for _, t := range affected[e.VulnID] {
			it := threatalert.QueueItem{TenantID: t, VulnID: key}
			if !queued[it] {
				queued[it] = true
				items = append(items, it)
			}
		}
	}
	return flush()
}

// cardWithdrawn resolves a withdrawn card's alerts and queues the
// vulnerabilities their organizations had grouped into it, so each is
// planned on its own again (its earlier alert reopens if still affected).
func (p *Planner) cardWithdrawn(ctx context.Context, cardID string, flush func() error) error {
	if err := flush(); err != nil {
		return err
	}
	n, err := p.store.ResolveVuln(ctx, cardID, threatalert.ReasonCardWithdrawn, p.now())
	if err != nil {
		return err
	}
	items, err := p.store.GroupedInto(ctx, cardID)
	if err != nil {
		return err
	}
	if n > 0 || len(items) > 0 {
		p.logger.Info("emerging threats resolved: advisory card withdrawn", "card_id", cardID, "alerts", n, "requeued", len(items))
	}
	return p.store.Enqueue(ctx, items)
}

// cardUpdated queues the vulnerabilities whose alerts were grouped into the
// card but which the new revision no longer groups (removed from the card,
// or the card is no longer reviewed): each is planned on its own again, so
// its alert reopens if it is still affected.
func (p *Planner) cardUpdated(ctx context.Context, cardID string, flush func() error) error {
	items, err := p.store.GroupedInto(ctx, cardID)
	if err != nil || len(items) == 0 {
		return err
	}
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.VulnID)
	}
	groups, err := p.store.CardsGrouping(ctx, ids)
	if err != nil {
		return err
	}
	var out []threatalert.QueueItem
	for _, it := range items {
		if groups[it.VulnID] != cardID {
			out = append(out, it)
		}
	}
	if len(out) == 0 {
		return nil
	}
	if err := flush(); err != nil {
		return err
	}
	p.logger.Info("emerging threats requeued: left an advisory card", "card_id", cardID, "requeued", len(out))
	return p.store.Enqueue(ctx, out)
}

// keysFor maps vulnerability ids to alert keys (a reviewed advisory card's
// id for the vulnerabilities it groups), without repeats.
func (p *Planner) keysFor(ctx context.Context, vulnIDs []string) ([]string, error) {
	groups, err := p.store.CardsGrouping(ctx, vulnIDs)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(vulnIDs))
	seen := map[string]bool{}
	for _, v := range vulnIDs {
		if c := groups[v]; c != "" {
			v = c
		}
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

// QueueVulns queues an organization's vulnerabilities (the matcher created
// findings for them).
func (p *Planner) QueueVulns(ctx context.Context, tenantID shared.ID, vulnIDs []string) error {
	keys, err := p.keysFor(ctx, vulnIDs)
	if err != nil {
		return err
	}
	items := make([]threatalert.QueueItem, 0, len(keys))
	seen := map[string]bool{}
	for _, v := range keys {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		items = append(items, threatalert.QueueItem{TenantID: tenantID, VulnID: v})
	}
	return p.store.Enqueue(ctx, items)
}

// baselines computes the alerts of the active window for organizations
// never planned, without any immediate message; one baseline digest
// follows.
func (p *Planner) baselines(ctx context.Context, rs *runState, st *Stats, deadline time.Time) error {
	ids, err := p.store.TenantsWithoutBaseline(ctx, baselinePerRun)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if !p.now().Before(deadline) {
			return nil
		}
		pol := p.policyOf(ctx, rs, id)
		state, err := p.store.TenantState(ctx, id)
		if err != nil {
			return err
		}
		if !pol.active {
			// Re-checked hourly: turning alerts on later baselines then.
			state.BaselineAt = nil
			if err := p.store.SaveTenantState(ctx, state); err != nil {
				return err
			}
			continue
		}
		now := p.now()
		vulns, err := p.store.ActiveWindowVulns(ctx, id, now.Add(-EventWindow), now.Add(-KEVWindow))
		if err != nil {
			return err
		}
		if vulns, err = p.keysFor(ctx, vulns); err != nil {
			return err
		}
		for _, v := range vulns {
			if err := p.plan(ctx, rs, id, v, true); err != nil {
				p.logger.Warn("emerging threat baseline not planned", "tenant_id", id.String(), "vuln_id", v, "error", err)
			}
		}
		state.BaselineAt = &now
		state.BaselineDigestDue = len(vulns) > 0
		if err := p.store.SaveTenantState(ctx, state); err != nil {
			return err
		}
		st.Baselined++
	}
	return nil
}

// plan opens, updates, escalates or resolves one organization's alert for
// one vulnerability. baseline: computing the organization's first view
// (nothing is sent for what it finds).
//
//nolint:cyclop // one rule per branch of the alert lifecycle
func (p *Planner) plan(ctx context.Context, rs *runState, tenantID shared.ID, vulnID string, baseline bool) error {
	pol := p.policyOf(ctx, rs, tenantID)
	if !pol.active {
		return nil
	}
	if !baseline {
		state, err := p.store.TenantState(ctx, tenantID)
		if err != nil {
			return err
		}
		if state.BaselineAt == nil {
			return nil // the baseline will cover it
		}
	}
	if keys, err := p.keysFor(ctx, []string{vulnID}); err != nil {
		return err
	} else if len(keys) == 1 {
		vulnID = keys[0] // grouped into a card since it was queued
	}
	now := p.now()
	v, err := p.store.Vuln(ctx, vulnID, now.Add(-EventWindow))
	if err != nil || v == nil {
		return err
	}
	if v.Rejected {
		// Rejected upstream: its alerts were resolved and stay so.
		return nil
	}
	existing, err := p.store.AlertByVuln(ctx, tenantID, vulnID)
	if err != nil {
		return err
	}
	inWindow := v.LastEventAt != nil || (v.InKEV && v.KEVDateAdded != nil && now.Sub(*v.KEVDateAdded) <= KEVWindow)
	if existing == nil && !inWindow {
		return nil
	}
	assets, err := p.store.AffectedAssets(ctx, tenantID, vulnID)
	if err != nil {
		return err
	}
	if len(assets) == 0 {
		if existing == nil || !existing.State.IsOpen() {
			return nil
		}
		existing.State, existing.StateReason, existing.ResolvedAt = threatalert.StateResolved, threatalert.ReasonFixed, &now
		existing.StateChangedAt = &now
		existing.DigestPending = true
		existing.Counts(nil)
		return p.store.SaveAlert(ctx, existing, nil)
	}
	b, tier := threatalert.Score(*v, assets, now)
	level := threatalert.LevelFor(b, tier, *v, assets, pol.settings, pol.vm.SeverityPasses(v.Severity))

	a := existing
	if a == nil {
		a = &threatalert.Alert{TenantID: tenantID, VulnID: vulnID, State: threatalert.StateNew, Baseline: baseline,
			NotifiedLevel: threatalert.NotifiedNone}
	}
	prevTier, prevKEV := a.Tier, a.InKEV
	// What the alert held when it was last planned: growth is a host it did
	// not hold, or a host in a stronger tier, never one more port of a host.
	var before []threatalert.Asset
	if existing != nil {
		if before, err = p.store.PlannedAssets(ctx, tenantID, existing.ID); err != nil {
			return err
		}
	}
	a.Title = threatalert.Title(vulnID, firstProduct(assets))
	if v.Title != "" {
		a.Title = threatalert.CardTitle(v.Title, v.CardReported)
	}
	a.Severity = normSeverity(v.Severity)
	a.Level, a.Tier, a.ETS, a.Breakdown = level, tier, b.Total, b
	a.InKEV, a.KEVRansomware, a.EPSS = v.InKEV, v.KEVRansomware, v.EPSS
	a.LastEventKind, a.EventAt, a.SourceAt = v.LastEventKind, v.LastEventAt, v.SourceAt
	a.Counts(assets)

	if v.CardID != "" && !v.CardReported && a.State.IsOpen() {
		// The card's alert carries on the triage of the alerts it groups:
		// the strongest open state (acknowledged or remediating).
		inherited, err := p.store.GroupedTriage(ctx, tenantID, v.Grouped)
		if err != nil {
			return err
		}
		if st := threatalert.StrongerTriage(a.State, inherited); st != a.State {
			a.State, a.StateChangedAt = st, &now
		}
	}

	switch a.State {
	case threatalert.StateNotAffected:
		expired := a.SuppressedUntil != nil && now.After(*a.SuppressedUntil)
		if expired || (existing != nil && threatalert.ReopenedBy(a.StateReason, prevTier, tier, v.InKEV && !prevKEV)) {
			a.State, a.StateReason, a.StateNote, a.SuppressedUntil, a.StateChangedAt = threatalert.StateNew, "", "", nil, &now
			a.NotifiedLevel = threatalert.NotifiedNone
		}
	case threatalert.StateResolved:
		// Affected again (a finding reopened, a new asset).
		a.State, a.StateReason, a.ResolvedAt, a.StateChangedAt = threatalert.StateNew, "", nil, &now
		a.NotifiedLevel = threatalert.NotifiedNone
	}

	switch {
	case baseline && existing == nil:
		// The first view of an organization sends nothing immediate.
		a.NotifiedLevel, a.NotifiedTier = notifiedFor(level), string(tier)
	case a.State.IsOpen():
		if a.NotifiedLevel == string(threatalert.LevelImmediate) && a.NotifiedTier == string(threatalert.TierPossible) &&
			tier == threatalert.TierConfirmed && level == threatalert.LevelImmediate {
			// Possibly affected became confirmed: one more message.
			a.NotifiedLevel = string(threatalert.LevelDigest)
		}
		if level.Rank() >= threatalert.LevelDigest.Rank() &&
			(levelRank(a.NotifiedLevel) < threatalert.LevelDigest.Rank() || threatalert.HostsGrew(before, assets)) {
			a.DigestPending = true
		}
	}
	if err := p.store.SaveAlert(ctx, a, assets); err != nil {
		return err
	}
	if v.CardID != "" && !v.CardReported && len(v.Grouped) > 0 {
		// The card's alert carries its vulnerabilities on: their own open
		// alerts in this organization are resolved, with the card id. A
		// reported card (not yet reviewed) groups nothing.
		if _, err := p.store.ResolveGrouped(ctx, tenantID, v.CardID, v.Grouped, now); err != nil {
			return err
		}
	}
	if a.State.IsOpen() && level == threatalert.LevelImmediate && a.NotifiedLevel != string(threatalert.LevelImmediate) {
		rs.touched[tenantID] = true
	}
	return nil
}

func notifiedFor(l threatalert.Level) string {
	if l == threatalert.LevelListed {
		return threatalert.NotifiedNone
	}
	return string(l)
}

func levelRank(notified string) int { return threatalert.Level(notified).Rank() }

func normSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "none":
		return s
	}
	return ""
}

func firstProduct(assets []threatalert.Asset) string {
	for _, a := range assets {
		if a.Kind != threatalert.MatchPossible && a.Product != "" {
			return a.Product
		}
	}
	for _, a := range assets {
		if a.Product != "" {
			return a.Product
		}
	}
	return ""
}
