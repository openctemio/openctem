package postgres

// Immediate alerts of web endpoint changes (docs/architecture/web-content-pipeline.md).
// Two kinds go out at once: a critical sensitive path that appeared
// (web_sensitive_new) and a sensitive or API endpoint that lost its
// authentication (web_auth_lost). Everything else stays in the change feed
// and the weekly digest.
//
// The alert is written in the recording transaction, through the same
// notification outbox, hourly budget and attribution rules as the exposure
// alerts (easmalert): an origin a person rejected, a deleted origin, an
// origin nobody confirmed yet and an origin held by a private bounty
// program never get an immediate alert. A fingerprint per (tenant, origin,
// kind, template) with the tenant's alert lifetime keeps a flapping
// endpoint to one alert per lifetime.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/domain/easmalert"
	"github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

// WebAlerter announces web endpoint changes. It shares the exposure
// alerter's throttle, outbox and clock.
type WebAlerter struct {
	base *EASMAlerter
}

var _ WebAlertSink = (*WebAlerter)(nil)

// NewWebAlerter builds the alerter on the exposure alerter.
func NewWebAlerter(base *EASMAlerter) *WebAlerter { return &WebAlerter{base: base} }

// AlertInTx announces the candidates of one origin inside tx. It is
// tenant-scoped on every read and write: the origin is looked up by tenant
// and id, so an origin id of another tenant matches nothing and nothing is
// announced.
func (a *WebAlerter) AlertInTx(ctx context.Context, tx *sql.Tx, tenantID, originAssetID shared.ID, cands []webendpoint.AlertCandidate) error {
	if a == nil || a.base == nil || len(cands) == 0 {
		return nil
	}
	var name string
	var deleted, restricted bool
	var state string
	err := tx.QueryRowContext(ctx, `
		SELECT a.name, a.deleted_at IS NOT NULL, COALESCE(aa.state, ''),
		       EXISTS (SELECT 1 FROM assets ra WHERE ra.tenant_id = a.tenant_id AND ra.id = a.id AND `+orgRestrictedAssetSQL+`)
		FROM assets a
		LEFT JOIN asset_attributions aa ON aa.asset_id = a.id AND aa.tenant_id = a.tenant_id
		WHERE a.tenant_id = $1 AND a.id = $2`, tenantID.String(), originAssetID.String()).Scan(&name, &deleted, &state, &restricted)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("load web alert origin: %w", err)
	}
	// Only an origin the tenant owns gets an immediate alert; the rest is
	// still in the change feed. A restricted origin never leaves its
	// program's channels, which these alerts do not target.
	if restricted || easmalert.Classify(easmalert.Exposure{Severity: "high", HasAsset: true, AssetDeleted: deleted, Attribution: state}) != easmalert.Immediate {
		return nil
	}

	now := a.base.now().UTC()
	sent, err := a.base.lockThrottle(ctx, tx, tenantID, now)
	if err != nil {
		return err
	}
	allowed := max(a.base.budget-sent, 0)
	if allowed == 0 {
		return nil // over budget: the change stays in the feed and the digest
	}
	life, err := a.base.reappearAfter(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return easmalert.SeverityRank(cands[i].Severity) > easmalert.SeverityRank(cands[j].Severity)
	})
	enqueued := 0
	for _, c := range cands {
		if enqueued >= allowed {
			break
		}
		fresh, err := claimWebFingerprint(ctx, tx, tenantID, c.Fingerprint(tenantID.String(), originAssetID.String()), now, life)
		if err != nil {
			return err
		}
		if !fresh {
			continue
		}
		if err := a.enqueue(ctx, tx, tenantID, originAssetID, name, c); err != nil {
			return err
		}
		enqueued++
	}
	if enqueued > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE easm_alert_throttle SET sent = sent + $2 WHERE tenant_id = $1`,
			tenantID.String(), enqueued); err != nil {
			return fmt.Errorf("update easm alert throttle: %w", err)
		}
	}
	return nil
}

// claimWebFingerprint records the alert's fingerprint and reports whether
// the alert may go out: the fingerprint is new, or its last alert is older
// than the lifetime.
func claimWebFingerprint(ctx context.Context, tx *sql.Tx, tenantID shared.ID, fp string, now time.Time, life time.Duration) (bool, error) {
	var got string
	err := tx.QueryRowContext(ctx, `
		INSERT INTO web_alert_fingerprints (tenant_id, fingerprint, last_alerted_at) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET last_alerted_at = excluded.last_alerted_at
			WHERE web_alert_fingerprints.last_alerted_at <= $3::timestamptz - make_interval(secs => $4)
		RETURNING fingerprint`, tenantID.String(), fp, now, life.Seconds()).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim web alert fingerprint: %w", err)
	}
	return true, nil
}

func (a *WebAlerter) enqueue(ctx context.Context, tx *sql.Tx, tenantID, originID shared.ID, origin string, c webendpoint.AlertCandidate) error {
	epID, err := uuid.Parse(c.EndpointID)
	if err != nil {
		return fmt.Errorf("endpoint id: %w", err)
	}
	var title, what string
	switch c.Kind {
	case webendpoint.AlertSensitiveNew:
		title = fmt.Sprintf("New %s sensitive web path: %s %s", c.Severity, c.Method, c.PathTemplate)
		what = "A sensitive path (" + c.CatalogKey + ") appeared"
	default:
		title = fmt.Sprintf("Web endpoint lost authentication: %s %s", c.Method, c.PathTemplate)
		what = "An endpoint that required authentication answers without it"
	}
	entry := outbox.NewOutbox(outbox.OutboxParams{
		TenantID:      tenantID,
		EventType:     easmAlertEventType,
		AggregateType: "web_endpoint",
		AggregateID:   &epID,
		Title:         truncateRunes(title+" on "+origin, 500),
		Body:          what + " on " + origin + ". Open the attack surface changes to review it.",
		Severity:      outbox.Severity(c.Severity),
		URL:           "/attack-surface/changes",
		Metadata: map[string]any{
			"channel":     easmAlertChannel,
			"change_kind": c.Kind,
			"severity":    c.Severity,
			"asset_id":    originID.String(),
			"asset_name":  origin,
			"catalog_key": c.CatalogKey,
			"fingerprint": c.Fingerprint(tenantID.String(), originID.String()),
		},
	})
	if err := a.base.outbox.CreateInTx(ctx, tx, entry); err != nil {
		return fmt.Errorf("enqueue web alert: %w", err)
	}
	return nil
}
