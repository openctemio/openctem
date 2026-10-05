package postgres

// EASM alerts through the notification outbox (research/22 P0-7, decision
// E4). Policy: pkg/domain/easmalert. Architecture: docs/architecture/easm.md.
//
// Every write here runs inside the caller's transaction, the one that
// inserted or reopened the exposure rows, so an exposure and its alert
// commit or roll back together.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/easmalert"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	easmAlertEventType     = "new_exposure"
	easmDigestAggregate    = "easm_digest"
	easmExposureAggregate  = "exposure"
	easmAlertChannel       = "easm"
	easmAlertMaxIDsPerCall = 5000
)

// easmDigestNamespace derives the digest's aggregate id from tenant and due
// date, so one tenant has one pending digest per day.
var easmDigestNamespace = uuid.MustParse("6f1c1f0e-9a4e-4f57-9c1e-2e5d8b7a3c41")

// EASMAlerter enqueues EASM exposure alerts in the caller's transaction.
type EASMAlerter struct {
	outbox *OutboxRepository
	budget int
	now    func() time.Time
}

// NewEASMAlerter builds the alerter with the default hourly budget.
func NewEASMAlerter(db *DB) *EASMAlerter {
	return &EASMAlerter{outbox: NewOutboxRepository(db), budget: easmalert.DefaultHourlyImmediateBudget, now: time.Now}
}

// WithHourlyBudget overrides the per-tenant hourly budget of immediate
// alerts (tests, operators). Values below 0 are treated as 0.
func (a *EASMAlerter) WithHourlyBudget(n int) *EASMAlerter {
	a.budget = max(n, 0)
	return a
}

type easmAlertRow struct {
	id, eventType, severity, title, source, fingerprint string
	assetID, assetName                                  string
	exp                                                 easmalert.Exposure
}

// EnqueueInTx announces the tenant's exposures with the given ids (rows the
// transaction just inserted or reopened). Ids of another tenant match
// nothing.
func (a *EASMAlerter) EnqueueInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []string, reason easmalert.Reason) error {
	if a == nil || len(ids) == 0 {
		return nil
	}
	if len(ids) > easmAlertMaxIDsPerCall {
		ids = ids[:easmAlertMaxIDsPerCall]
	}
	rows, err := a.load(ctx, tx, tenantID, ids)
	if err != nil {
		return err
	}
	var immediate, digest []easmAlertRow
	for _, r := range rows {
		switch easmalert.Classify(r.exp) {
		case easmalert.Immediate:
			immediate = append(immediate, r)
		case easmalert.Digest:
			digest = append(digest, r)
		case easmalert.Skip:
		}
	}
	if len(immediate) == 0 && len(digest) == 0 {
		return nil
	}
	now := a.now().UTC()
	// The throttle row is locked for the rest of the transaction: it
	// serializes this tenant's alert writes, including the digest merge.
	sent, err := a.lockThrottle(ctx, tx, tenantID, now)
	if err != nil {
		return err
	}
	// The most severe go out first when the budget runs short.
	sort.SliceStable(immediate, func(i, j int) bool {
		return easmalert.SeverityRank(immediate[i].severity) > easmalert.SeverityRank(immediate[j].severity)
	})
	allowed := min(max(a.budget-sent, 0), len(immediate))
	throttled := immediate[allowed:]
	immediate = immediate[:allowed]

	for _, r := range immediate {
		if err := a.enqueueImmediate(ctx, tx, tenantID, r, reason); err != nil {
			return err
		}
	}
	if len(immediate) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE easm_alert_throttle SET sent = sent + $2 WHERE tenant_id = $1`,
			tenantID.String(), len(immediate)); err != nil {
			return fmt.Errorf("update easm alert throttle: %w", err)
		}
	}
	if len(digest) == 0 && len(throttled) == 0 {
		return nil
	}
	return a.mergeDigest(ctx, tx, tenantID, now, reason, digest, throttled)
}

func (a *EASMAlerter) load(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []string) ([]easmAlertRow, error) {
	q, err := tx.QueryContext(ctx, `
		SELECT e.id, e.event_type, e.severity, e.title, COALESCE(e.source, ''), e.fingerprint,
		       COALESCE(e.asset_id::text, ''), COALESCE(a.name, ''),
		       (a.id IS NOT NULL AND a.deleted_at IS NOT NULL), COALESCE(aa.state, '')
		FROM exposure_events e
		LEFT JOIN assets a ON a.id = e.asset_id AND a.tenant_id = e.tenant_id
		LEFT JOIN asset_attributions aa ON aa.asset_id = e.asset_id AND aa.tenant_id = e.tenant_id
		WHERE e.tenant_id = $1 AND e.id = ANY($2::uuid[])`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("load exposures to alert: %w", err)
	}
	defer q.Close()
	var out []easmAlertRow
	for q.Next() {
		var r easmAlertRow
		var deleted bool
		var state string
		if err := q.Scan(&r.id, &r.eventType, &r.severity, &r.title, &r.source, &r.fingerprint,
			&r.assetID, &r.assetName, &deleted, &state); err != nil {
			return nil, fmt.Errorf("scan exposure to alert: %w", err)
		}
		r.exp = easmalert.Exposure{Severity: r.severity, HasAsset: r.assetID != "", AssetDeleted: deleted, Attribution: state}
		out = append(out, r)
	}
	return out, q.Err()
}

// lockThrottle returns how many immediate alerts the tenant already sent in
// the current window, rolling the window over when it is an hour old.
func (a *EASMAlerter) lockThrottle(ctx context.Context, tx *sql.Tx, tenantID shared.ID, now time.Time) (int, error) {
	var sent int
	err := tx.QueryRowContext(ctx, `
		INSERT INTO easm_alert_throttle (tenant_id, window_start, sent) VALUES ($1, $2, 0)
		ON CONFLICT (tenant_id) DO UPDATE SET
			window_start = CASE WHEN easm_alert_throttle.window_start <= $2 - INTERVAL '1 hour'
				THEN $2 ELSE easm_alert_throttle.window_start END,
			sent = CASE WHEN easm_alert_throttle.window_start <= $2 - INTERVAL '1 hour'
				THEN 0 ELSE easm_alert_throttle.sent END
		RETURNING sent`, tenantID.String(), now).Scan(&sent)
	if err != nil {
		return 0, fmt.Errorf("lock easm alert throttle: %w", err)
	}
	return sent, nil
}

func (a *EASMAlerter) enqueueImmediate(ctx context.Context, tx *sql.Tx, tenantID shared.ID, r easmAlertRow, reason easmalert.Reason) error {
	id, err := uuid.Parse(r.id)
	if err != nil {
		return fmt.Errorf("exposure id: %w", err)
	}
	verb := "New"
	if reason == easmalert.ReasonReopened {
		verb = "Reopened"
	}
	body := fmt.Sprintf("%s external exposure (%s) from %s.", verb, exposure.EventType(r.eventType).String(), sourceLabel(r.source))
	if r.assetName != "" {
		body += fmt.Sprintf(" Asset: %s (%s).", r.assetName, easmalert.Label(r.exp))
	}
	entry := outbox.NewOutbox(outbox.OutboxParams{
		TenantID:      tenantID,
		EventType:     easmAlertEventType,
		AggregateType: easmExposureAggregate,
		AggregateID:   &id,
		Title:         truncateRunes(fmt.Sprintf("%s %s exposure: %s", verb, r.severity, r.title), 500),
		Body:          body,
		Severity:      outbox.Severity(r.severity),
		URL:           "/exposures/" + r.id,
		Metadata:      alertMetadata(r, reason, false),
	})
	if err := a.outbox.CreateInTx(ctx, tx, entry); err != nil {
		return fmt.Errorf("enqueue easm alert: %w", err)
	}
	return nil
}

func alertMetadata(r easmAlertRow, reason easmalert.Reason, throttled bool) map[string]any {
	m := map[string]any{
		"channel":     easmAlertChannel,
		"exposure_id": r.id,
		"event_type":  r.eventType,
		"severity":    r.severity,
		"source":      r.source,
		"attribution": easmalert.Label(r.exp),
		"reason":      string(reason),
		"fingerprint": r.fingerprint,
	}
	if r.assetID != "" {
		m["asset_id"] = r.assetID
		m["asset_name"] = r.assetName
	}
	if throttled {
		m["throttled"] = true
	}
	return m
}

type easmDigest struct {
	Digest     bool             `json:"digest"`
	Channel    string           `json:"channel"`
	DueAt      string           `json:"due_at"`
	Count      int              `json:"count"`
	Throttled  int              `json:"throttled"`
	BySeverity map[string]int   `json:"by_severity"`
	ByLabel    map[string]int   `json:"by_attribution"`
	Items      []map[string]any `json:"items"`
}

// mergeDigest adds exposures to the tenant's pending digest for the next due
// time, creating it when there is none. The caller holds the throttle lock.
func (a *EASMAlerter) mergeDigest(ctx context.Context, tx *sql.Tx, tenantID shared.ID, now time.Time,
	reason easmalert.Reason, digest, throttled []easmAlertRow,
) error {
	due := easmalert.NextDigestAt(now)
	aggID := uuid.NewSHA1(easmDigestNamespace, []byte(tenantID.String()+"|"+due.Format(time.RFC3339)))

	var (
		rowID    string
		rawMeta  []byte
		severity string
	)
	d := easmDigest{Digest: true, Channel: easmAlertChannel, DueAt: due.Format(time.RFC3339),
		BySeverity: map[string]int{}, ByLabel: map[string]int{}}
	err := tx.QueryRowContext(ctx, `
		SELECT id, metadata, severity FROM notification_outbox
		WHERE tenant_id = $1 AND aggregate_type = $2 AND aggregate_id = $3 AND status = 'pending'
		FOR UPDATE`, tenantID.String(), easmDigestAggregate, aggID.String()).Scan(&rowID, &rawMeta, &severity)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		severity = "info"
	case err != nil:
		return fmt.Errorf("load easm digest: %w", err)
	default:
		if err := json.Unmarshal(rawMeta, &d); err != nil {
			return fmt.Errorf("decode easm digest: %w", err)
		}
		if d.BySeverity == nil {
			d.BySeverity = map[string]int{}
		}
		if d.ByLabel == nil {
			d.ByLabel = map[string]int{}
		}
	}
	add := func(r easmAlertRow, wasThrottled bool) {
		d.Count++
		d.BySeverity[r.severity]++
		d.ByLabel[easmalert.Label(r.exp)]++
		if wasThrottled {
			d.Throttled++
		}
		severity = easmalert.MaxSeverity(severity, r.severity)
		if len(d.Items) < easmalert.MaxDigestItems {
			d.Items = append(d.Items, alertMetadata(r, reason, wasThrottled))
		}
	}
	for _, r := range throttled {
		add(r, true)
	}
	for _, r := range digest {
		add(r, false)
	}
	meta, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("encode easm digest: %w", err)
	}
	title := fmt.Sprintf("EASM daily digest: %d new or reopened external exposures", d.Count)
	body := digestBody(d)
	if rowID != "" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE notification_outbox SET title = $3, body = $4, severity = $5, metadata = $6, updated_at = now()
			WHERE id = $1 AND tenant_id = $2`, rowID, tenantID.String(), title, body, severity, meta); err != nil {
			return fmt.Errorf("update easm digest: %w", err)
		}
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO notification_outbox (id, tenant_id, event_type, aggregate_type, aggregate_id,
			title, body, severity, url, metadata, status, scheduled_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '/exposures', $9, 'pending', $10, now(), now())`,
		shared.NewID().String(), tenantID.String(), easmAlertEventType, easmDigestAggregate, aggID.String(),
		title, body, severity, meta, due); err != nil {
		return fmt.Errorf("create easm digest: %w", err)
	}
	return nil
}

func digestBody(d easmDigest) string {
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := d.BySeverity[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", sev, n))
		}
	}
	b := fmt.Sprintf("%d external exposures were found or reopened (%s).", d.Count, strings.Join(parts, ", "))
	if n := d.ByLabel[easmalert.LabelUnverified]; n > 0 {
		b += fmt.Sprintf(" %d are on assets whose ownership is not confirmed yet.", n)
	}
	if d.Throttled > 0 {
		b += fmt.Sprintf(" %d were held back from immediate alerts by the hourly limit.", d.Throttled)
	}
	return b + " Review them on the Exposures page."
}

func sourceLabel(source string) string {
	switch source {
	case "cert_transparency":
		return "Certificate Transparency"
	case "easm_dns":
		return "the EASM DNS checks"
	case "":
		return "an unknown source"
	}
	return source
}
