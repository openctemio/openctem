package postgres

// Emerging-threat alerts keyed by an advisory card (docs/rfcs/RFC-117-
// emerging-threat-alerts.md, "Advisory cards"): one alert per organization
// and card, the card's vulnerabilities grouped inside it.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/advisory"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
	"github.com/openctemio/openctem/server/pkg/domain/vulncatalog"
)

// Confidence of an asset whose version a reviewed card's range places,
// before any finding exists: likely, never confirmed.
const cardRangeConfidence = 60

// cardVuln is a card's public facts: its own title and summary, the
// strongest severity, exploitation, KEV, EPSS and CVSS facts of the card and
// the vulnerabilities it groups (a card never rates a grouped vulnerability
// lower than its own record does). A withdrawn card reads as rejected. A
// reported card (fast lane) adds no exploitation of its own.
func (r *ThreatAlertRepository) cardVuln(ctx context.Context, cardID string, eventsSince time.Time) (*threatalert.Vuln, error) {
	c, err := loadCard(ctx, r.db, cardID)
	if err != nil || c == nil {
		return nil, err
	}
	published := c.PublishedAt
	v := threatalert.Vuln{ID: c.ID, CardID: c.ID, Title: c.Title, Description: c.Summary,
		Published: &published, Rejected: c.Withdrawn(), CardReported: c.Reported()}
	ids := c.VulnIDs()
	v.Grouped = ids
	if !c.Reported() {
		v.Exploitation = c.ExploitationStatus()
		urls := map[string]string{}
		for _, s := range c.Sources {
			urls[s.ID] = s.URL
		}
		for _, id := range c.Exploitation.Sources {
			if u := urls[id]; u != "" {
				v.ExploitationSources = append(v.ExploitationSources, u)
			}
		}
	}
	// What reviewed cards (this one included) state for the grouped ids.
	ex, err := exploitationFor(ctx, r.db, ids)
	if err != nil {
		return nil, err
	}
	for _, e := range ex {
		v.Exploitation = advisory.Stronger(v.Exploitation, e)
	}
	// The catalog facts of the grouped ids come through the catalog reader
	// (RFC-143 R3), never from its tables.
	facts, err := NewVulnCatalogReader(r.db).Facts(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("card %s facts: %w", c.ID, err)
	}
	// KEV and EPSS are read by id on their own: a CVE listed in KEV before
	// its catalog record arrives has no fact, and the card must not lose it.
	rd := NewVulnCatalogReader(r.db)
	kevs, err := rd.KEVs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("card %s kev: %w", c.ID, err)
	}
	scores, err := rd.EPSS(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("card %s epss: %w", c.ID, err)
	}
	cf := foldCardFacts(facts, kevs, scores)
	ev, err := lastVulnEvent(ctx, r.db, c.ID, ids, eventsSince)
	if err != nil {
		return nil, fmt.Errorf("card %s facts: %w", c.ID, err)
	}
	sevs, score, vector := cf.severities, cf.score, cf.vector
	inKEV, kevAdded, ransomware, epss := cf.inKEV, cf.kevAdded, cf.ransomware, cf.epss
	lastKind, lastAt, lastSource := ev.kind, ev.at, ev.sourceAt
	v.Severity = threatalert.CardSeverity(c.Reported(), c.Severity.Level, sevs...)
	v.CVSSScore = score
	v.CVSSVector = vector
	v.InKEV, v.KEVRansomware = inKEV, ransomware
	v.KEVDateAdded = kevAdded
	v.EPSS = epss
	v.LastEventKind = lastKind
	v.LastEventAt = lastAt
	v.SourceAt = lastSource
	if v.SourceAt == nil {
		v.SourceAt = v.LastEventAt
	}
	return &v, nil
}

// cardFacts are the catalog facts of a card's grouped ids, folded the way a
// card states them: the strongest CVSS score (and its vector), any KEV
// listing (earliest date added, any ransomware use), the highest EPSS score
// and the distinct severities.
type cardFacts struct {
	severities []string
	score      *float64
	vector     string
	inKEV      bool
	kevAdded   *time.Time
	ransomware bool
	epss       *float64
}

func foldCardFacts(facts []vulncatalog.Fact, kevs []vulncatalog.KEV, scores []vulncatalog.EPSS) cardFacts {
	var out cardFacts
	seen := map[string]bool{}
	for _, f := range facts {
		if sev := strings.ToLower(strings.TrimSpace(f.Severity)); sev != "" && !seen[sev] {
			seen[sev] = true
			out.severities = append(out.severities, sev)
		}
		if f.CVSSScore != nil && (out.score == nil || *f.CVSSScore > *out.score) {
			sc := *f.CVSSScore
			out.score, out.vector = &sc, f.CVSSVector
		}
	}
	for _, k := range kevs {
		out.inKEV = true
		out.ransomware = out.ransomware || k.Ransomware
		if k.DateAdded != nil && (out.kevAdded == nil || k.DateAdded.Before(*out.kevAdded)) {
			d := *k.DateAdded
			out.kevAdded = &d
		}
	}
	for _, e := range scores {
		if out.epss == nil || e.Score > *out.epss {
			sc := e.Score
			out.epss = &sc
		}
	}
	sort.Strings(out.severities)
	return out
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

// ResolveGrouped (see threatalert.PlannerStore). The person's note and the
// actor of the last change stay on the row.
func (r *ThreatAlertRepository) ResolveGrouped(ctx context.Context, tenantID shared.ID, cardID string, vulnIDs []string, at time.Time) (int, error) {
	if len(vulnIDs) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE threat_alerts SET state = 'resolved', state_reason = $3, grouped_into_card = $4, resolved_at = $5,
			state_changed_at = $5, digest_pending = true, updated_at = now()
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
		WHERE grouped_into_card = $2 AND state = 'resolved' AND state_reason = $1
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

// GroupedTriage (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) GroupedTriage(ctx context.Context, tenantID shared.ID, vulnIDs []string) (threatalert.State, error) {
	best := threatalert.StateNew
	if len(vulnIDs) == 0 {
		return best, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT state FROM threat_alerts
		WHERE tenant_id = $1 AND vuln_id = ANY($2::text[]) AND state IN ('acknowledged', 'remediating')`,
		tenantID.String(), pq.Array(vulnIDs))
	if err != nil {
		return best, fmt.Errorf("grouped triage: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		if err := rows.Scan(&st); err != nil {
			return best, err
		}
		best = threatalert.StrongerTriage(best, threatalert.State(st))
	}
	return best, rows.Err()
}
