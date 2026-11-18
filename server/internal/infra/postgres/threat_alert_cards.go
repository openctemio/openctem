package postgres

// Emerging-threat alerts keyed by an advisory card (docs/rfcs/RFC-117-
// emerging-threat-alerts.md, "Advisory cards"): one alert per organization
// and card, the card's vulnerabilities grouped inside it.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/advisory"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
)

// Confidence of an asset whose version a reviewed card's range places,
// before any finding exists: likely, never confirmed.
const cardRangeConfidence = 60

// cardVuln is a card's public facts: its own title, severity, summary and
// exploitation, and the strongest KEV, EPSS and CVSS facts of the
// vulnerabilities it groups. A withdrawn card reads as rejected.
func (r *ThreatAlertRepository) cardVuln(ctx context.Context, cardID string, eventsSince time.Time) (*threatalert.Vuln, error) {
	c, err := loadCard(ctx, r.db, cardID)
	if err != nil || c == nil {
		return nil, err
	}
	published := c.PublishedAt
	v := threatalert.Vuln{ID: c.ID, CardID: c.ID, Title: c.Title, Severity: c.Severity.Level, Description: c.Summary,
		Published: &published, Rejected: c.Withdrawn(), Exploitation: c.ExploitationStatus()}
	urls := map[string]string{}
	for _, s := range c.Sources {
		urls[s.ID] = s.URL
	}
	for _, id := range c.Exploitation.Sources {
		if u := urls[id]; u != "" {
			v.ExploitationSources = append(v.ExploitationSources, u)
		}
	}
	ids := c.VulnIDs()
	v.Grouped = ids
	var score, epss sql.NullFloat64
	var vector, lastKind sql.NullString
	var kevAdded, lastAt, lastSource sql.NullTime
	var inKEV, ransomware sql.NullBool
	err = r.db.QueryRowContext(ctx, `
		SELECT
			(SELECT max(cvss_score)::float8 FROM cve_records WHERE cve_id = ANY($1::text[])),
			(SELECT cvss_vector FROM cve_records WHERE cve_id = ANY($1::text[]) ORDER BY cvss_score DESC NULLS LAST LIMIT 1),
			(SELECT count(*) > 0 FROM kev_catalog WHERE cve_id = ANY($1::text[])),
			(SELECT min(date_added)::timestamptz FROM kev_catalog WHERE cve_id = ANY($1::text[])),
			(SELECT bool_or(known_ransomware_campaign_use = 'Known') FROM kev_catalog WHERE cve_id = ANY($1::text[])),
			(SELECT max(epss_score)::float8 FROM epss_scores WHERE cve_id = ANY($1::text[])),
			ev.kind, ev.at, ev.source_at
		FROM (SELECT 1) x
		LEFT JOIN LATERAL (
			SELECT kind, at, source_at FROM vuln_events
			WHERE (vuln_id = $2 OR vuln_id = ANY($1::text[])) AND at >= $3 ORDER BY at DESC, id DESC LIMIT 1
		) ev ON true`, pq.Array(ids), c.ID, eventsSince).
		Scan(&score, &vector, &inKEV, &kevAdded, &ransomware, &epss, &lastKind, &lastAt, &lastSource)
	if err != nil {
		return nil, fmt.Errorf("card %s facts: %w", c.ID, err)
	}
	if score.Valid {
		f := score.Float64
		v.CVSSScore = &f
	}
	v.CVSSVector = vector.String
	v.InKEV, v.KEVRansomware = inKEV.Bool, ransomware.Bool
	v.KEVDateAdded = timePtr(kevAdded)
	if epss.Valid {
		f := epss.Float64
		v.EPSS = &f
	}
	v.LastEventKind = lastKind.String
	v.LastEventAt = timePtr(lastAt)
	v.SourceAt = timePtr(lastSource)
	if v.SourceAt == nil {
		v.SourceAt = v.LastEventAt
	}
	return &v, nil
}

// cardCandidates lists the organization's assets that run a product the
// card names with a known version, which have no finding yet: inside a
// published range they are likely, where the card's versions are not
// published (or the version does not parse) they are possible, outside
// every range they are left out. Assets already in have are skipped.
func (r *ThreatAlertRepository) cardCandidates(ctx context.Context, tenantID shared.ID, c *advisory.Card, have []threatalert.Asset) ([]threatalert.Asset, error) {
	seen := map[shared.ID]bool{}
	for _, a := range have {
		seen[a.AssetID] = true
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.asset_id, a.name, a.asset_type, p.name, v.raw, p.part, p.cpe_vendor, p.cpe_product,
			(a.exposure = 'public' OR COALESCE(a.is_internet_accessible, false)), COALESCE(a.criticality, '')
		FROM advisory_card_products acp
		JOIN software_products p ON p.tenant_id IS NULL AND p.part = acp.part AND p.cpe_vendor = acp.cpe_vendor AND p.cpe_product = acp.cpe_product
		JOIN asset_software s ON s.tenant_id = $1 AND s.product_id = p.id AND s.superseded_at IS NULL
		JOIN software_versions v ON v.id = s.software_version_id AND v.normalized IS NOT NULL AND v.raw <> ''
		JOIN assets a ON a.tenant_id = $1 AND a.id = s.asset_id AND a.status <> 'archived'
		WHERE acp.card_id = $2
		ORDER BY a.name, s.asset_id
		LIMIT 5000`, tenantID.String(), c.ID)
	if err != nil {
		return nil, fmt.Errorf("card candidates: %w", err)
	}
	defer rows.Close()
	best := map[shared.ID]int{}
	var out []threatalert.Asset
	for rows.Next() {
		var a threatalert.Asset
		var part, vendor, product string
		if err := rows.Scan(&a.AssetID, &a.Name, &a.Type, &a.Product, &a.Version, &part, &vendor, &product,
			&a.InternetFacing, &a.Criticality); err != nil {
			return nil, fmt.Errorf("card candidates: %w", err)
		}
		if seen[a.AssetID] {
			continue
		}
		switch c.MatchVersion(strings.TrimSpace(part)+":"+vendor+":"+product, a.Version) {
		case advisory.VersionAffected:
			a.Kind, a.Confidence = threatalert.MatchLikely, cardRangeConfidence
		case advisory.VersionUnknown:
			a.Kind, a.Confidence = threatalert.MatchPossible, 30
		default:
			continue
		}
		a.Product, a.Version = clipStr(a.Product, 200), clipStr(a.Version, 64)
		// One row per asset, the strongest match.
		if i, ok := best[a.AssetID]; ok {
			if out[i].Kind == threatalert.MatchPossible && a.Kind == threatalert.MatchLikely {
				out[i] = a
			}
			continue
		}
		best[a.AssetID] = len(out)
		out = append(out, a)
	}
	return out, rows.Err()
}

// CardsGrouping (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) CardsGrouping(ctx context.Context, vulnIDs []string) (map[string]string, error) {
	out := map[string]string{}
	if len(vulnIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT ON (v.vuln_id) v.vuln_id, v.card_id FROM advisory_card_vulns v
		JOIN advisory_cards c ON c.card_id = v.card_id AND c.review_state = 'reviewed'
		WHERE v.vuln_id = ANY($1::text[])
		ORDER BY v.vuln_id, v.card_id`, pq.Array(vulnIDs))
	if err != nil {
		return nil, fmt.Errorf("cards grouping: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var vuln, card string
		if err := rows.Scan(&vuln, &card); err != nil {
			return nil, err
		}
		out[vuln] = card
	}
	return out, rows.Err()
}

// ResolveGrouped (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) ResolveGrouped(ctx context.Context, tenantID shared.ID, cardID string, vulnIDs []string, at time.Time) (int, error) {
	if len(vulnIDs) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE threat_alerts SET state = 'resolved', state_reason = $3, state_note = $4, resolved_at = $5,
			state_changed_at = $5, state_changed_by = NULL, updated_at = now()
		WHERE tenant_id = $1 AND vuln_id = ANY($2::text[]) AND state IN `+openAlertStates,
		tenantID.String(), pq.Array(vulnIDs), threatalert.ReasonGroupedIntoCard, cardID, at)
	if err != nil {
		return 0, fmt.Errorf("resolve grouped alerts: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// GroupedInto (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) GroupedInto(ctx context.Context, cardID string) ([]threatalert.QueueItem, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id, vuln_id FROM threat_alerts
		WHERE state = 'resolved' AND state_reason = $1 AND state_note = $2
		ORDER BY tenant_id, vuln_id LIMIT 10000`, threatalert.ReasonGroupedIntoCard, cardID)
	if err != nil {
		return nil, fmt.Errorf("grouped alerts: %w", err)
	}
	defer rows.Close()
	var out []threatalert.QueueItem
	for rows.Next() {
		var it threatalert.QueueItem
		if err := rows.Scan(&it.TenantID, &it.VulnID); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
