// Package assetdiscovery turns attack-surface growth into tenant
// notifications: newly discovered internet-facing assets, and existing assets
// a re-scan turned internet-facing. Each notice is one in-app
// `asset_discovered` notification plus one `new_asset` outbox event (fanned
// out to the tenant's Slack/Teams/email/webhook/SIEM integrations that opted
// into it).
//
// A single recon run can create thousands of assets across many ingest
// batches, so notifications are coalesced per tenant with a throttle:
//
//   - The first internet-facing discovery for a tenant notifies immediately
//     (leading edge) and opens a cool-down window.
//   - Discoveries arriving during the window are buffered (deduplicated by
//     asset id) and sent as ONE summary when the window closes (trailing
//     edge), which opens the next window.
//   - An empty window closes quietly and the tenant is back to idle.
//
// So a tenant receives at most one notification per window however large the
// run, and none is lost while the process is up. State is in-memory and
// per-process: with N API replicas a tenant can get up to N per window, and
// a buffered summary is lost on a hard stop (Stop flushes on graceful
// shutdown). The authoritative record is the `appeared` state history the
// ingest pipeline writes, which the "What changed" view reads.
package assetdiscovery

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// DefaultWindow is the per-tenant cool-down between two notifications.
	DefaultWindow = 15 * time.Minute

	// maxListed caps how many assets are named in one notification body and
	// carried in outbox metadata; the count always covers the whole batch.
	maxListed = 10

	// maxTrackedPerBatch bounds the dedup set of one pending summary so a
	// runaway run cannot grow memory without limit. Beyond it assets are only
	// counted (they were already de-duplicated upstream: ingest only reports
	// assets it actually inserted).
	maxTrackedPerBatch = 10000

	// sendTimeout bounds one delivery (outbox insert + in-app insert).
	sendTimeout = 30 * time.Second

	// ChangesURL is the UI "What changed" page (Discovery > What changed).
	ChangesURL = "/assets/changes"
)

// changesURL deep-links the "What changed" view that lists the notified assets.
func changesURL(count, exposed int) string {
	switch exposed {
	case 0:
		return ChangesURL + "?view=appeared&internet=true"
	case count:
		return ChangesURL + "?view=newly_exposed"
	default:
		return ChangesURL
	}
}

// runURL deep-links the Runs page with one run open.
func runURL(runID shared.ID) string { return "/scans/runs?run=" + runID.String() }

type stepRunKey struct{}

// WithStepRun marks ctx as an ingest of a report from a scan task: the
// assets it creates were found by that step run's scan run. The ingest sets
// it from the bound command, never from the report body.
func WithStepRun(ctx context.Context, stepRunID *shared.ID) context.Context {
	if stepRunID == nil || stepRunID.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, stepRunKey{}, *stepRunID)
}

func stepRunFrom(ctx context.Context) (shared.ID, bool) {
	id, ok := ctx.Value(stepRunKey{}).(shared.ID)
	return id, ok
}

// RunResolver finds the scan run a step run belongs to, inside the tenant:
// false for a step run or run of another tenant, or an unknown one.
type RunResolver interface {
	RunOfStepRun(ctx context.Context, tenantID, stepRunID shared.ID) (shared.ID, bool)
}

// SetRunResolver wires the lookup that lets a notification link to the run
// that found its assets. Without it the notification links to the changes
// view. Call before the notifier receives assets.
func (n *Notifier) SetRunResolver(r RunResolver) { n.runs = r }

// Enqueuer is the slice of outbox.Service the notifier needs.
type Enqueuer interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// InAppNotifier is the slice of the in-app notification service it needs.
type InAppNotifier interface {
	Notify(ctx context.Context, params notification.NotificationParams) error
}

// timer is the part of *time.Timer the notifier uses (a test seam).
type timer interface{ Stop() bool }

type assetRef struct {
	id       shared.ID
	name     string
	typ      string
	exposure string
	// becameExposed: an existing asset turned internet-facing (vs. new).
	becameExposed bool
	// runID is the scan run that found the asset (zero when unknown).
	runID shared.ID
}

type tenantState struct {
	cooling bool                   // a window is open
	pending []assetRef             // listed assets buffered during the window
	seen    map[shared.ID]struct{} // dedup set for this window
	count   int                    // all buffered assets (listed or not)
	exposed int                    // of count: existing assets that became internet-facing
	runs    map[shared.ID]struct{} // distinct runs that found the buffered assets (capped at 2)
	noRun   bool                   // some buffered asset has no known run
	t       timer
}

// Notifier coalesces internet-facing discoveries into throttled notifications.
type Notifier struct {
	outbox Enqueuer
	inApp  InAppNotifier
	window time.Duration
	logger *logger.Logger
	runs   RunResolver

	// afterFunc schedules the end of a window (time.AfterFunc in production).
	afterFunc func(d time.Duration, f func()) timer

	mu      sync.Mutex
	tenants map[shared.ID]*tenantState
	stopped bool
}

// NewNotifier builds a notifier. Either sink may be nil (that channel is then
// skipped); window <= 0 uses DefaultWindow.
func NewNotifier(o Enqueuer, inApp InAppNotifier, window time.Duration, log *logger.Logger) *Notifier {
	if window <= 0 {
		window = DefaultWindow
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &Notifier{
		outbox:  o,
		inApp:   inApp,
		window:  window,
		logger:  log.With("service", "asset-discovery-notifier"),
		tenants: make(map[shared.ID]*tenantState),
		afterFunc: func(d time.Duration, f func()) timer {
			return time.AfterFunc(d, f)
		},
	}
}

// IsInternetFacing reports whether an asset is reachable from the internet.
func IsInternetFacing(a *asset.Asset) bool {
	return a.IsInternetFacing()
}

// AssetsDiscovered is the ingest callback for newly created assets: it keeps
// the internet-facing ones and either notifies now (tenant idle) or buffers
// them for the end-of-window summary.
func (n *Notifier) AssetsDiscovered(ctx context.Context, tenantID shared.ID, assets []*asset.Asset) {
	n.publish(ctx, tenantID, assets, false)
}

// AssetsExposed is the ingest callback for existing assets a re-scan turned
// internet-facing. They share the tenant's window with new discoveries.
func (n *Notifier) AssetsExposed(ctx context.Context, tenantID shared.ID, assets []*asset.Asset) {
	n.publish(ctx, tenantID, assets, true)
}

// publish never blocks on I/O while holding the lock.
func (n *Notifier) publish(ctx context.Context, tenantID shared.ID, assets []*asset.Asset, becameExposed bool) {
	refs := make([]assetRef, 0, len(assets))
	var runID shared.ID
	if n.runs != nil {
		if step, ok := stepRunFrom(ctx); ok {
			if id, found := n.runs.RunOfStepRun(ctx, tenantID, step); found {
				runID = id
			}
		}
	}
	for _, a := range assets {
		if a == nil || !IsInternetFacing(a) {
			continue
		}
		// Never trust a mismatched tenant on the entity: the callback's tenant
		// comes from the authenticated sensor, and it alone decides where the
		// notification goes.
		if !a.TenantID().IsZero() && a.TenantID() != tenantID {
			continue
		}
		refs = append(refs, assetRef{
			id: a.ID(), name: a.Name(), typ: string(a.Type()), exposure: string(a.Exposure()),
			becameExposed: becameExposed, runID: runID,
		})
	}
	if len(refs) == 0 {
		return
	}

	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return
	}
	st := n.tenants[tenantID]
	if st == nil {
		st = &tenantState{}
		n.tenants[tenantID] = st
	}
	if st.cooling {
		st.add(refs)
		n.mu.Unlock()
		return
	}
	// Idle tenant: notify now and open a window.
	st.cooling = true
	st.t = n.afterFunc(n.window, func() { n.windowClosed(tenantID) })
	n.mu.Unlock()

	unique := dedupe(refs)
	exposed := 0
	for _, r := range unique {
		if r.becameExposed {
			exposed++
		}
	}
	var runs map[shared.ID]struct{}
	noRun := false
	for _, r := range unique {
		runs, noRun = noteRun(runs, noRun, r.runID)
	}
	n.send(tenantID, unique, len(unique), exposed, singleRun(runs, noRun))
}

// noteRun adds one asset's run to the window's set, keeping at most two ids
// (more than one run is all the summary needs to know).
func noteRun(runs map[shared.ID]struct{}, noRun bool, id shared.ID) (map[shared.ID]struct{}, bool) {
	if id.IsZero() {
		return runs, true
	}
	if runs == nil {
		runs = make(map[shared.ID]struct{}, 2)
	}
	if len(runs) < 2 {
		runs[id] = struct{}{}
	}
	return runs, noRun
}

// singleRun is the run every asset of a summary came from, or nil when they
// came from several runs or any has no known run.
func singleRun(runs map[shared.ID]struct{}, noRun bool) *shared.ID {
	if noRun || len(runs) != 1 {
		return nil
	}
	for id := range runs {
		return &id
	}
	return nil
}

func (st *tenantState) add(refs []assetRef) {
	if st.seen == nil {
		st.seen = make(map[shared.ID]struct{})
	}
	for _, r := range refs {
		if _, dup := st.seen[r.id]; dup {
			continue
		}
		if len(st.seen) < maxTrackedPerBatch {
			st.seen[r.id] = struct{}{}
		}
		st.count++
		if r.becameExposed {
			st.exposed++
		}
		st.runs, st.noRun = noteRun(st.runs, st.noRun, r.runID)
		if len(st.pending) < maxListed {
			st.pending = append(st.pending, r)
		}
	}
}

func dedupe(refs []assetRef) []assetRef {
	seen := make(map[shared.ID]struct{}, len(refs))
	out := refs[:0:0]
	for _, r := range refs {
		if _, dup := seen[r.id]; dup {
			continue
		}
		seen[r.id] = struct{}{}
		out = append(out, r)
	}
	return out
}

// windowClosed sends the buffered summary (if any) and opens the next window,
// or returns the tenant to idle when nothing arrived.
func (n *Notifier) windowClosed(tenantID shared.ID) {
	n.mu.Lock()
	st := n.tenants[tenantID]
	if st == nil || n.stopped {
		n.mu.Unlock()
		return
	}
	if st.count == 0 {
		delete(n.tenants, tenantID)
		n.mu.Unlock()
		return
	}
	listed, count, exposed := st.pending, st.count, st.exposed
	run := singleRun(st.runs, st.noRun)
	st.pending, st.seen, st.count, st.exposed, st.runs, st.noRun = nil, nil, 0, 0, nil, false
	st.t = n.afterFunc(n.window, func() { n.windowClosed(tenantID) })
	n.mu.Unlock()

	n.send(tenantID, listed, count, exposed, run)
}

// Stop cancels open windows and flushes every buffered summary. Call it on
// graceful shutdown so a pending summary is not dropped.
func (n *Notifier) Stop() {
	type flush struct {
		tenant  shared.ID
		listed  []assetRef
		count   int
		exposed int
		run     *shared.ID
	}
	n.mu.Lock()
	n.stopped = true
	var flushes []flush
	for id, st := range n.tenants {
		if st.t != nil {
			st.t.Stop()
		}
		if st.count > 0 {
			flushes = append(flushes, flush{id, st.pending, st.count, st.exposed, singleRun(st.runs, st.noRun)})
		}
	}
	n.tenants = make(map[shared.ID]*tenantState)
	n.mu.Unlock()

	for _, f := range flushes {
		n.send(f.tenant, f.listed, f.count, f.exposed, f.run)
	}
}

// send delivers one notification describing `count` assets (`exposed` of them
// existing assets that became internet-facing), naming `listed`. runID is the
// one scan run that found them all, when known: a summary of several assets
// then links to that run instead of the changes view.
func (n *Notifier) send(tenantID shared.ID, listed []assetRef, count, exposed int, runID *shared.ID) {
	if count == 0 || len(listed) == 0 {
		return
	}
	if len(listed) > maxListed {
		listed = listed[:maxListed]
	}
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()

	title, body := describe(listed, count, exposed)
	link := changesURL(count, exposed)
	if runID != nil && count > 1 {
		link = runURL(*runID)
	}

	if n.outbox != nil {
		params := outbox.EnqueueParams{
			TenantID:      tenantID,
			EventType:     string(integration.EventTypeNewAsset),
			AggregateType: "asset",
			Title:         title,
			Body:          body,
			// A new internet-facing asset is attack-surface growth, not a
			// finding: severity is a fixed label, and new_asset is exempt from
			// the per-integration severity filter (SeverityFilterApplies), so
			// the event-type switch alone decides delivery.
			Severity: "medium",
			URL:      link,
			Metadata: metadata(listed, count, exposed, runID),
		}
		if count == 1 {
			if id, err := uuid.Parse(listed[0].id.String()); err == nil {
				params.AggregateID = &id
			}
		}
		if err := n.outbox.Enqueue(ctx, params); err != nil {
			n.logger.Warn("failed to enqueue new-asset notification",
				"tenant_id", tenantID.String(), "count", count, "error", err)
		}
	}

	if n.inApp != nil {
		params := notification.NotificationParams{
			TenantID:         tenantID,
			Audience:         notification.AudienceAll,
			NotificationType: notification.TypeAssetDiscovered,
			Severity:         notification.SeverityMedium,
			Title:            title,
			Body:             body,
			ResourceType:     "asset",
			URL:              link,
		}
		if count == 1 {
			id := listed[0].id
			params.ResourceID = &id
			params.URL = "/assets/" + id.String()
		}
		if err := n.inApp.Notify(ctx, params); err != nil {
			n.logger.Warn("failed to create in-app new-asset notification",
				"tenant_id", tenantID.String(), "count", count, "error", err)
		}
	}

	n.logger.Info("new internet-facing asset notification sent",
		"tenant_id", tenantID.String(), "count", count)
}

func describe(listed []assetRef, count, exposed int) (title, body string) {
	if count == 1 {
		a := listed[0]
		if a.becameExposed {
			return fmt.Sprintf("Asset now internet-facing: %s", a.name),
				fmt.Sprintf("A known %s is now reachable from the internet according to the latest scan (exposure: %s).", humanType(a.typ), a.exposure)
		}
		return fmt.Sprintf("New internet-facing asset: %s", a.name),
			fmt.Sprintf("A %s was discovered and is reachable from the internet (exposure: %s).", humanType(a.typ), a.exposure)
	}
	names := make([]string, 0, len(listed))
	for _, a := range listed {
		names = append(names, a.name)
	}
	sort.Strings(names)
	list := strings.Join(names, ", ")
	if more := count - len(listed); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	switch {
	case exposed == 0:
		return fmt.Sprintf("%d new internet-facing assets discovered", count),
			fmt.Sprintf("%d new internet-facing assets were discovered, including: %s.", count, list)
	case exposed == count:
		return fmt.Sprintf("%d assets became internet-facing", count),
			fmt.Sprintf("%d known assets are now reachable from the internet, including: %s.", count, list)
	default:
		return fmt.Sprintf("%d assets newly exposed to the internet", count),
			fmt.Sprintf("%d new and %d existing assets are now reachable from the internet, including: %s.", count-exposed, exposed, list)
	}
}

func humanType(t string) string {
	if t == "" {
		return "asset"
	}
	return strings.ReplaceAll(t, "_", " ")
}

func metadata(listed []assetRef, count, exposed int, runID *shared.ID) map[string]any {
	items := make([]map[string]any, 0, len(listed))
	for _, a := range listed {
		items = append(items, map[string]any{
			"id":             a.id.String(),
			"name":           a.name,
			"type":           a.typ,
			"exposure":       a.exposure,
			"became_exposed": a.becameExposed,
		})
	}
	md := map[string]any{
		"asset_count":         count,
		"new_asset_count":     count - exposed,
		"newly_exposed_count": exposed,
		"assets":              items,
		"internet_facing":     true,
		"truncated":           count > len(listed),
	}
	if runID != nil {
		md["run_id"] = runID.String()
	}
	return md
}
