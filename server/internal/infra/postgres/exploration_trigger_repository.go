package postgres

// The trigger states the exploration rules read
// (docs/architecture/exploration.md, "Rules"). Each read is bound to one
// tenant on every table it touches, returns a bounded number of subjects in
// a stable order, and leaves out subjects that already have a live lead of
// the lead type or one closed within exploration.ReaskAfter, so a pass
// always moves on to subjects not asked about yet.

import (
	"context"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/domain/vulnmatch"
)

// ExplorationTriggerRepository implements exploration.TriggerStore.
type ExplorationTriggerRepository struct{ db *DB }

var _ exploration.TriggerStore = (*ExplorationTriggerRepository)(nil)

// NewExplorationTriggerRepository creates the repository.
func NewExplorationTriggerRepository(db *DB) *ExplorationTriggerRepository {
	return &ExplorationTriggerRepository{db: db}
}

// triggerMaxLimit bounds one rule's read.
const triggerMaxLimit = 500

// triggerEvidenceMax bounds the findings one candidate cites.
const triggerEvidenceMax = 5

// notAskedSQL leaves out an asset (a.id) that already has a live lead of the
// lead type ($2) or one closed within $3 seconds.
const notAskedSQL = `NOT EXISTS (
	SELECT 1 FROM exploration_leads l
	WHERE l.tenant_id = a.tenant_id AND l.subject_asset_id = a.id AND l.lead_type = $2
	  AND (l.state IN ('proposed', 'awaiting_approval', 'open', 'running', 'blocked')
	       OR l.closed_at > now() - make_interval(secs => $3)))`

// triggerAssetSQL: the asset is live (not soft-deleted) and in use (not
// archived).
var triggerAssetSQL = liveAssetSQL("a") + " AND a.status <> 'archived'"

func triggerLimit(limit int) int {
	if limit <= 0 || limit > triggerMaxLimit {
		return triggerMaxLimit
	}
	return limit
}

// readCandidates runs a candidate query whose columns are the asset id,
// type, sub type and an array of finding ids to cite.
func (r *ExplorationTriggerRepository) readCandidates(ctx context.Context, q string, args ...any) ([]exploration.Candidate, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []exploration.Candidate
	for rows.Next() {
		var (
			c        exploration.Candidate
			typ, sub string
			findings []string
		)
		if err := rows.Scan(&c.AssetID, &typ, &sub, pq.Array(&findings)); err != nil {
			return nil, err
		}
		c.Type, c.SubType = asset.AssetType(typ), sub
		id := c.AssetID
		c.Evidence = append(c.Evidence, exploration.Link{EndKind: exploration.EndAsset, EndID: &id})
		for _, f := range findings {
			fid, err := shared.IDFromString(f)
			if err != nil {
				return nil, err
			}
			c.Evidence = append(c.Evidence, exploration.Link{EndKind: exploration.EndFinding, EndID: &fid})
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func reaskSeconds() float64 { return exploration.ReaskAfter.Seconds() }

// openStatusArray is the open finding statuses as a SQL array argument.
func openStatusArray() any {
	st := vulnerability.OpenStatuses()
	out := make([]string, len(st))
	for i, s := range st {
		out[i] = string(s)
	}
	return pq.Array(out)
}

// DanglingAliases implements exploration.TriggerStore. Only the platform's
// own DNS check (source easm_dns) counts; an imported exposure does not.
func (r *ExplorationTriggerRepository) DanglingAliases(ctx context.Context, tenantID shared.ID, leadType string, limit int) ([]exploration.Candidate, error) {
	out, err := r.readCandidates(ctx, `
		SELECT a.id, a.asset_type, COALESCE(a.sub_type, ''), ARRAY[]::text[]
		FROM assets a
		WHERE a.tenant_id = $1 AND `+triggerAssetSQL+`
		  AND a.asset_type IN ('domain', 'subdomain')
		  AND EXISTS (SELECT 1 FROM exposure_events e
		              WHERE e.tenant_id = a.tenant_id AND e.asset_id = a.id
		                AND e.event_type = 'dangling_cname' AND e.state = 'active' AND e.source = 'easm_dns')
		  AND NOT EXISTS (SELECT 1 FROM exposure_events e
		                  WHERE e.tenant_id = a.tenant_id AND e.asset_id = a.id
		                    AND e.event_type = 'subdomain_takeover' AND e.state IN ('active', 'in_progress'))
		  AND `+notAskedSQL+`
		ORDER BY a.id
		LIMIT $4`, tenantID.String(), leadType, reaskSeconds(), triggerLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("read dangling aliases: %w", err)
	}
	return out, nil
}

// UnconfirmedCriticalMatches implements exploration.TriggerStore. Only the
// platform's version matcher's findings count (tool version-match, not since
// reported by a scanner), each cited as evidence.
func (r *ExplorationTriggerRepository) UnconfirmedCriticalMatches(ctx context.Context, tenantID shared.ID, leadType string, limit int) ([]exploration.Candidate, error) {
	out, err := r.readCandidates(ctx, `
		SELECT a.id, a.asset_type, COALESCE(a.sub_type, ''),
		       ARRAY(SELECT f.id::text FROM findings f
		             WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND `+unconfirmedMatchSQL+`
		             ORDER BY f.is_in_kev DESC, f.id LIMIT $6)
		FROM assets a
		WHERE a.tenant_id = $1 AND `+triggerAssetSQL+`
		  AND EXISTS (SELECT 1 FROM findings f
		              WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND `+unconfirmedMatchSQL+`)
		  AND `+notAskedSQL+`
		ORDER BY a.id
		LIMIT $4`, tenantID.String(), leadType, reaskSeconds(), triggerLimit(limit),
		openStatusArray(), triggerEvidenceMax, vulnmatch.LikelyThreshold)
	if err != nil {
		return nil, fmt.Errorf("read unconfirmed matches: %w", err)
	}
	return out, nil
}

// unconfirmedMatchSQL: an open ($5) version-match finding, in KEV or
// critical, below the likely threshold ($7).
var unconfirmedMatchSQL = strings.Join([]string{
	"f.status = ANY($5::text[])",
	"f.tool_name = 'version-match'",
	"COALESCE(f.last_seen_tool, f.tool_name) = 'version-match'",
	"(f.is_in_kev OR f.severity = 'critical')",
	"COALESCE(f.confidence, 0) < $7",
}, " AND ")

// GoneWithOpenFindings implements exploration.TriggerStore.
func (r *ExplorationTriggerRepository) GoneWithOpenFindings(ctx context.Context, tenantID shared.ID, leadType string, limit int) ([]exploration.Candidate, error) {
	out, err := r.readCandidates(ctx, `
		SELECT a.id, a.asset_type, COALESCE(a.sub_type, ''),
		       ARRAY(SELECT f.id::text FROM findings f
		             WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND f.status = ANY($5::text[])
		             ORDER BY f.id LIMIT $6)
		FROM asset_liveness lv
		JOIN assets a ON a.tenant_id = lv.tenant_id AND a.id = lv.asset_id
		WHERE lv.tenant_id = $1 AND lv.state = 'gone' AND `+triggerAssetSQL+`
		  AND EXISTS (SELECT 1 FROM findings f
		              WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND f.status = ANY($5::text[]))
		  AND `+notAskedSQL+`
		ORDER BY a.id
		LIMIT $4`, tenantID.String(), leadType, reaskSeconds(), triggerLimit(limit), openStatusArray(), triggerEvidenceMax)
	if err != nil {
		return nil, fmt.Errorf("read gone assets with open findings: %w", err)
	}
	return out, nil
}
