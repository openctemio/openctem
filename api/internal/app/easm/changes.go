package easm

// Typed attack-surface changes and the weekly "what changed" digest.
// Design: docs/rfcs/RFC-080-attack-surface-changes-and-digest.md.

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/easmchange"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ChangeStore reads typed changes and claims weekly digests.
type ChangeStore interface {
	ListChanges(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, q easmchange.Query) (*easmchange.Page, error)
	CountChanges(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, from, to time.Time) (map[easmchange.Kind]int, int, error)
	ClaimDigest(ctx context.Context, tenantID shared.ID, slot, from time.Time, counts map[easmchange.Kind]int, total int) (bool, error)
	ReleaseDigest(ctx context.Context, tenantID shared.ID, slot time.Time) error
}

// ChangeService serves the typed change feed, narrowed to the caller's data
// scope.
type ChangeService struct {
	store     ChangeStore
	dataScope *datascope.Enforcer
	now       func() time.Time
}

// NewChangeService creates the service. A nil enforcer means unrestricted
// reads.
func NewChangeService(store ChangeStore, scope *datascope.Enforcer) *ChangeService {
	return &ChangeService{store: store, dataScope: scope, now: func() time.Time { return time.Now().UTC() }}
}

// List returns a page of changes in the query's window.
func (s *ChangeService) List(ctx context.Context, tenantID shared.ID, q easmchange.Query) (*easmchange.Page, error) {
	if err := q.Normalize(s.now()); err != nil {
		return nil, err
	}
	var scope *shared.DataScope
	if s.dataScope != nil {
		var err error
		if scope, err = s.dataScope.Resolve(ctx, tenantID); err != nil {
			return nil, fmt.Errorf("resolve data scope: %w", err)
		}
	}
	return s.store.ListChanges(ctx, tenantID, scope, q)
}

// DigestSettings reads the organization's attack-surface settings.
type DigestSettings interface {
	GetEASMSettings(ctx context.Context, tenantID string) (*tenant.EASMSettings, error)
}

// DigestEnqueuer is the slice of the notification outbox the digest needs.
type DigestEnqueuer interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// DigestInApp delivers an in-app notification to one user.
type DigestInApp interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// DigestAdmins lists a tenant's active owners and administrators.
type DigestAdmins interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// digestListed is how many changes a digest names.
const digestListed = 10

// digestHighlights are the kinds the digest names first.
var digestHighlights = []easmchange.Kind{
	easmchange.KindDNSDangling, easmchange.KindExposureNew, easmchange.KindWebSensitiveNew, easmchange.KindWebAuthLost,
	easmchange.KindPortOpened, easmchange.KindHostAdded, easmchange.KindCertExpiring,
}

// DigestJob sends each organization its weekly attack-surface digest.
type DigestJob struct {
	store    ChangeStore
	settings DigestSettings
	outbox   DigestEnqueuer
	inApp    DigestInApp
	admins   DigestAdmins
	log      *logger.Logger
	now      func() time.Time
}

// NewDigestJob creates the job. inApp and admins may be nil (channels only).
func NewDigestJob(store ChangeStore, settings DigestSettings, ob DigestEnqueuer, inApp DigestInApp, admins DigestAdmins, log *logger.Logger) *DigestJob {
	if log == nil {
		log = logger.NewNop()
	}
	return &DigestJob{store: store, settings: settings, outbox: ob, inApp: inApp, admins: admins, log: log,
		now: func() time.Time { return time.Now().UTC() }}
}

// SetClock replaces the clock (tests).
func (j *DigestJob) SetClock(now func() time.Time) { j.now = now }

// RunTenant sends the tenant's digest for the latest slot unless it is off
// or already sent. It reports whether a digest went out. A week with no
// change is recorded and sends nothing.
func (j *DigestJob) RunTenant(ctx context.Context, tenantID shared.ID) (bool, error) {
	es, err := j.settings.GetEASMSettings(ctx, tenantID.String())
	if err != nil {
		return false, fmt.Errorf("read easm settings: %w", err)
	}
	if es.WeeklyDigestDisabled {
		return false, nil
	}
	slot, from := easmchange.DigestSlot(j.now(), easmchange.Weekday(es.DigestWeekday))
	// The digest is the organization's: counts cover every asset. Names
	// reach only administrators (in-app) and the channels they configured.
	counts, total, err := j.store.CountChanges(ctx, tenantID, nil, from, slot)
	if err != nil {
		return false, err
	}
	claimed, err := j.store.ClaimDigest(ctx, tenantID, slot, from, counts, total)
	if err != nil || !claimed || total == 0 {
		return false, err
	}
	page, err := j.store.ListChanges(ctx, tenantID, nil, easmchange.Query{From: from, To: slot, Kinds: digestHighlights, Limit: digestListed})
	if err != nil {
		j.release(ctx, tenantID, slot)
		return false, err
	}
	title, body, link := digestMessage(counts, total, page.Items, from, slot)
	items := make([]map[string]any, 0, len(page.Items))
	for _, c := range page.Items {
		item := map[string]any{"kind": string(c.Kind), "asset_name": c.AssetName, "at": c.At}
		if c.Severity != "" {
			item["severity"] = c.Severity
		}
		items = append(items, item)
	}
	countMeta := make(map[string]int, len(counts))
	for k, n := range counts {
		countMeta[string(k)] = n
	}
	if j.outbox != nil {
		if err := j.outbox.Enqueue(ctx, outbox.EnqueueParams{
			TenantID: tenantID, EventType: string(integration.EventTypeAttackSurfaceDigest),
			AggregateType: "easm_weekly_digest", Title: title, Body: body, Severity: notificationdom.SeverityInfo, URL: link,
			Metadata: map[string]any{"channel": "easm", "counts": countMeta, "total": total,
				"from": from.Format(time.RFC3339), "to": slot.Format(time.RFC3339), "items": items},
		}); err != nil {
			j.release(ctx, tenantID, slot)
			return false, fmt.Errorf("enqueue easm digest: %w", err)
		}
	}
	j.notifyAdmins(ctx, tenantID, title, body, link)
	return true, nil
}

func (j *DigestJob) release(ctx context.Context, tenantID shared.ID, slot time.Time) {
	if err := j.store.ReleaseDigest(ctx, tenantID, slot); err != nil {
		j.log.Warn("easm digest: release failed; this week's digest is skipped", "tenant_id", tenantID.String(),
			"error", logger.SanitizeError(err))
	}
}

func (j *DigestJob) notifyAdmins(ctx context.Context, tenantID shared.ID, title, body, link string) {
	if j.inApp == nil || j.admins == nil {
		return
	}
	ids, err := j.admins.ActiveAdminIDs(ctx, tenantID)
	if err != nil {
		j.log.Warn("easm digest: administrators unreadable; in-app notice skipped", "tenant_id", tenantID.String(),
			"error", logger.SanitizeError(err))
		return
	}
	for _, id := range ids {
		uid := id
		if err := j.inApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeAttackSurfaceDigest, Title: title, Body: body,
			Severity: notificationdom.SeverityInfo, URL: link,
		}); err != nil {
			j.log.Warn("easm digest: in-app notice failed", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
}

// digestLabels name each kind in the digest text. Channel messages are
// rendered outside the web console, so they are English.
var digestLabels = map[easmchange.Kind][2]string{
	easmchange.KindHostAdded:    {"new host", "new hosts"},
	easmchange.KindHostRemoved:  {"host gone", "hosts gone"},
	easmchange.KindPortOpened:   {"new open port", "new open ports"},
	easmchange.KindPortClosed:   {"closed port", "closed ports"},
	easmchange.KindCertChanged:  {"new certificate", "new certificates"},
	easmchange.KindCertExpiring: {"expiring certificate", "expiring certificates"},
	easmchange.KindDNSChanged:   {"DNS change", "DNS changes"},
	easmchange.KindDNSDangling:  {"dangling DNS record", "dangling DNS records"},
	easmchange.KindTechChanged:  {"technology change", "technology changes"},
	easmchange.KindExposureNew:  {"new exposure", "new exposures"},

	easmchange.KindWebSensitiveNew:        {"new sensitive web path", "new sensitive web paths"},
	easmchange.KindWebAuthLost:            {"web endpoint without authentication", "web endpoints without authentication"},
	easmchange.KindWebParamAddedSensitive: {"new parameter on a sensitive web endpoint", "new parameters on sensitive web endpoints"},
}

// ChangesURL is the console page of the typed changes.
const ChangesURL = "/attack-surface/changes"

func digestMessage(counts map[easmchange.Kind]int, total int, items []easmchange.Change, from, to time.Time) (title, body, link string) {
	noun := "changes"
	if total == 1 {
		noun = "change"
	}
	title = fmt.Sprintf("Attack surface: %d %s in the week to %s", total, noun, to.Format("2 Jan 2006"))
	parts := make([]string, 0, len(counts))
	for _, k := range easmchange.AllKinds() {
		n := counts[k]
		if n == 0 {
			continue
		}
		label := digestLabels[k][1]
		if n == 1 {
			label = digestLabels[k][0]
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, label))
	}
	var b strings.Builder
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString(".")
	for _, c := range items {
		name := c.AssetName
		if name == "" {
			name = c.New
		}
		fmt.Fprintf(&b, "\n- %s: %s", digestLabels[c.Kind][0], name)
	}
	q := url.Values{}
	q.Set("from", from.Format(time.RFC3339))
	q.Set("to", to.Format(time.RFC3339))
	return title, b.String(), ChangesURL + "?" + q.Encode()
}
