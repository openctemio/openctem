package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/easmalert"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMDNSRepository backs the EASM DNS-only checks: which names are due, the
// per-name state, and resolving / reopening the exposures the checks own.
type EASMDNSRepository struct {
	db     *DB
	alerts *EASMAlerter
}

// NewEASMDNSRepository creates the repository.
func NewEASMDNSRepository(db *DB) *EASMDNSRepository { return &EASMDNSRepository{db: db} }

// WithAlerts makes ReopenAuto announce the exposures it reopens through the
// notification outbox, in the same transaction (research/22 P0-7).
func (r *EASMDNSRepository) WithAlerts(a *EASMAlerter) *EASMDNSRepository {
	r.alerts = a
	return r
}

var _ easmdns.Store = (*EASMDNSRepository)(nil)

// assetTypesFor lists the asset types each check looks at.
func assetTypesFor(kind string) []string {
	if kind == easmdns.KindEmail {
		return []string{"domain"}
	}
	return []string{"domain", "subdomain"}
}

// DueTargets returns the tenant's active assets of the check's types that are
// in the inventory or covered by the tenant's scope (dnsCheckInventoryStates)
// and that were not checked since checkedBefore,
// never-checked first, then oldest check, up to limit. The email check also
// takes the tenant's root-domain seeds and verified domains that have no
// domain asset, by name (Target.AssetID zero; 22c B3).
func (r *EASMDNSRepository) DueTargets(ctx context.Context, tenantID shared.ID, kind string, checkedBefore time.Time, limit int) ([]easmdns.Target, error) {
	targets, err := r.dueAssetTargets(ctx, tenantID, kind, checkedBefore, limit)
	if err != nil || kind != easmdns.KindEmail {
		return stripChecked(targets), err
	}
	names, err := r.dueNameTargets(ctx, tenantID, kind, checkedBefore, limit)
	if err != nil {
		return nil, err
	}
	targets = append(targets, names...)
	all := targets
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i].checked, all[j].checked
		if a.Valid != b.Valid {
			return !a.Valid // never checked first
		}
		if a.Valid && !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		return all[i].Name < all[j].Name
	})
	if len(all) > limit {
		all = all[:limit]
	}
	return stripChecked(all), nil
}

type dueTarget struct {
	easmdns.Target
	checked sql.NullTime
}

func stripChecked(in []dueTarget) []easmdns.Target {
	out := make([]easmdns.Target, 0, len(in))
	for _, t := range in {
		out = append(out, t.Target)
	}
	return out
}

// dnsCheckInventoryStates are the attribution states the DNS checks look at
// without a scope entry: the inventory (attribution.InInventory; an asset with
// no record counts as confirmed). A name still in review (needs_review,
// candidate; what a sensor reported lands there) is checked only while an
// active, unexpired domain scope entry of the tenant covers it and no approved
// exclusion removes it: otherwise a tenant, or a hostile sensor, could make the
// platform's resolver look up any third-party name (research/84 F9). Rejected
// names are never checked.
var dnsCheckInventoryStates = []string{"confirmed", "dependency", "monitor_only"}

// dnsScopeMatch is the SQL condition "this scope pattern covers a.name" for
// domain entries, matched as pkg/domain/scope and the scope coverage count
// match them: "x" is exactly x; "*.x" / "**.x" is x and every name below it.
// pattern is a column reference, never user input.
func dnsScopeMatch(pattern string) string {
	p := "lower(rtrim(trim(" + pattern + "), '.'))"
	root := "regexp_replace(" + p + ", '^\\*\\*?\\.', '')"
	host := "lower(rtrim(a.name, '.'))"
	return "(" + host + " = " + p + " OR ((" + p + " LIKE '*.%' OR " + p + " LIKE '**.%') AND (" +
		host + " = " + root + " OR right(" + host + ", length(" + root + ") + 1) = '.' || " + root + ")))"
}

func (r *EASMDNSRepository) dueAssetTargets(ctx context.Context, tenantID shared.ID, kind string, checkedBefore time.Time, limit int) ([]dueTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.name, s.last_checked_at
		FROM assets a
		LEFT JOIN asset_attributions aa ON aa.asset_id = a.id AND aa.tenant_id = a.tenant_id
		LEFT JOIN easm_dns_check_state s ON s.asset_id = a.id AND s.check_kind = $2
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1
		  AND a.asset_type = ANY($3)
		  AND a.status = 'active'
		  AND (s.last_checked_at IS NULL OR s.last_checked_at < $4)
		  AND (COALESCE(aa.state, 'confirmed') = ANY($6) OR (
		       aa.state IN ('needs_review', 'candidate')
		       AND EXISTS (SELECT 1 FROM scope_targets t
		            WHERE t.tenant_id = $1 AND t.status = 'active'
		              AND (t.expires_at IS NULL OR t.expires_at > now())
		              AND t.target_type IN ('domain', 'subdomain', 'email_domain')
		              AND `+dnsScopeMatch("t.pattern")+`)
		       AND NOT EXISTS (SELECT 1 FROM scope_exclusions e
		            WHERE e.tenant_id = $1 AND e.status = 'active' AND e.approved_at IS NOT NULL
		              AND (e.expires_at IS NULL OR e.expires_at > now())
		              AND e.exclusion_type IN ('domain', 'subdomain', 'email_domain')
		              AND `+dnsScopeMatch("e.pattern")+`)))
		ORDER BY s.last_checked_at ASC NULLS FIRST, a.name
		LIMIT $5`,
		tenantID.String(), kind, pq.Array(assetTypesFor(kind)), checkedBefore, limit, pq.Array(dnsCheckInventoryStates))
	if err != nil {
		return nil, fmt.Errorf("list dns check targets: %w", err)
	}
	defer rows.Close()
	var out []dueTarget
	for rows.Next() {
		var id, name string
		var checked sql.NullTime
		if err := rows.Scan(&id, &name, &checked); err != nil {
			return nil, err
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		out = append(out, dueTarget{Target: easmdns.Target{AssetID: aid, Name: strings.ToLower(strings.TrimSuffix(name, "."))}, checked: checked})
	}
	return out, rows.Err()
}

// dueNameTargets returns the roots of the tenant's permanent domain scope
// entries with discovery on (research/53 SC1), and its
// verified domains that no active domain asset covers and that no person
// rejected, due for the check.
func (r *EASMDNSRepository) dueNameTargets(ctx context.Context, tenantID shared.ID, kind string, checkedBefore time.Time, limit int) ([]dueTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH names AS (
			SELECT rtrim(regexp_replace(lower(pattern), '^\*\*?\.', ''), '.') AS name FROM scope_targets
			WHERE tenant_id = $1 AND status = 'active' AND expires_at IS NULL AND discovery
			  AND target_type IN ('domain', 'subdomain')
			UNION
			SELECT lower(domain) FROM verified_domains WHERE tenant_id = $1 AND status = 'verified'
		)
		SELECT n.name, s.last_checked_at
		FROM names n
		LEFT JOIN easm_dns_name_state s ON s.tenant_id = $1 AND s.name = n.name AND s.check_kind = $2
		WHERE NOT EXISTS (
				SELECT 1 FROM assets a WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
				  AND a.asset_type = 'domain' AND lower(a.name) = n.name)
		  AND NOT EXISTS (
				SELECT 1 FROM easm_tombstones t WHERE t.tenant_id = $1 AND t.name = n.name AND t.expires_at > now())
		  AND (s.last_checked_at IS NULL OR s.last_checked_at < $3)
		ORDER BY s.last_checked_at ASC NULLS FIRST, n.name
		LIMIT $4`,
		tenantID.String(), kind, checkedBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("list dns check name targets: %w", err)
	}
	defer rows.Close()
	var out []dueTarget
	for rows.Next() {
		var name string
		var checked sql.NullTime
		if err := rows.Scan(&name, &checked); err != nil {
			return nil, err
		}
		out = append(out, dueTarget{Target: easmdns.Target{Name: strings.TrimSuffix(name, ".")}, checked: checked})
	}
	return out, rows.Err()
}

// SaveState records the last outcome of one check on one asset. The asset
// must be the tenant's: the insert selects it with the tenant id.
func (r *EASMDNSRepository) SaveState(ctx context.Context, tenantID, assetID shared.ID, kind, outcome, lastErr string, at time.Time) error {
	if assetID.IsZero() {
		return fmt.Errorf("%w: a name target's state is saved with SaveNameState", shared.ErrValidation)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO easm_dns_check_state (tenant_id, asset_id, check_kind, last_checked_at, last_outcome, last_error)
		SELECT a.tenant_id, a.id, $3, $4, $5, $6 FROM assets a WHERE a.id = $2 AND a.tenant_id = $1 AND a.deleted_at IS NULL
		ON CONFLICT (asset_id, check_kind) DO UPDATE SET
			last_checked_at = EXCLUDED.last_checked_at,
			last_outcome    = EXCLUDED.last_outcome,
			last_error      = EXCLUDED.last_error`,
		tenantID.String(), assetID.String(), kind, at, outcome, lastErr)
	if err != nil {
		return fmt.Errorf("save dns check state: %w", err)
	}
	return nil
}

// SaveNameState records the last outcome of one check on a name target (a
// scope entry with discovery or verified domain with no domain asset).
func (r *EASMDNSRepository) SaveNameState(ctx context.Context, tenantID shared.ID, name, kind, outcome, lastErr string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO easm_dns_name_state (tenant_id, name, check_kind, last_checked_at, last_outcome, last_error)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, name, check_kind) DO UPDATE SET
			last_checked_at = EXCLUDED.last_checked_at,
			last_outcome    = EXCLUDED.last_outcome,
			last_error      = EXCLUDED.last_error`,
		tenantID.String(), strings.ToLower(name), kind, at, outcome, lastErr)
	if err != nil {
		return fmt.Errorf("save dns name check state: %w", err)
	}
	return nil
}

// ResolveAuto resolves the tenant's ACTIVE exposures of this source with the
// given fingerprints and records the transition. Accepted, false-positive and
// already-resolved exposures are left alone.
func (r *EASMDNSRepository) ResolveAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error) {
	return r.transition(ctx, `
		UPDATE exposure_events SET state = 'resolved', resolved_at = now(), resolved_by = NULL,
			resolution_notes = $4, updated_at = now()
		WHERE tenant_id = $1 AND source = $2 AND fingerprint = ANY($3) AND state = 'active'
		RETURNING id`, "active", "resolved", tenantID, source, fingerprints, note)
}

// ReopenAuto reopens exposures this check itself resolved (resolved_by NULL
// and its own note) that it finds again. A person's resolution or acceptance
// is never reopened.
func (r *EASMDNSRepository) ReopenAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error) {
	return r.transition(ctx, `
		UPDATE exposure_events SET state = 'active', resolved_at = NULL, resolution_notes = '', updated_at = now()
		WHERE tenant_id = $1 AND source = $2 AND fingerprint = ANY($3)
		  AND state = 'resolved' AND resolved_by IS NULL AND resolution_notes = $4
		RETURNING id`, "resolved", "active", tenantID, source, fingerprints, note)
}

func (r *EASMDNSRepository) transition(ctx context.Context, update, from, to string, tenantID shared.ID, source string, fingerprints []string, note string) (int, error) {
	if len(fingerprints) == 0 {
		return 0, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	ids, err := transitionedIDs(ctx, tx, update, tenantID, source, fingerprints, note)
	if err != nil {
		return 0, err
	}
	reason := "Reopened automatically: the DNS check finds the problem again."
	if to == "resolved" {
		reason = note
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO exposure_state_history (id, exposure_event_id, previous_state, new_state, changed_by, reason, created_at)
			VALUES ($1, $2, $3, $4, NULL, $5, now())`,
			shared.NewID().String(), id, from, to, reason); err != nil {
			return 0, fmt.Errorf("record exposure transition: %w", err)
		}
	}
	if to == "active" && r.alerts != nil {
		if err := r.alerts.EnqueueInTx(ctx, tx, tenantID, ids, easmalert.ReasonReopened); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}

func transitionedIDs(ctx context.Context, tx *sql.Tx, update string, tenantID shared.ID, source string, fingerprints []string, note string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, update, tenantID.String(), source, pq.Array(fingerprints), note)
	if err != nil {
		return nil, fmt.Errorf("transition exposures: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// easmDNSLeaseTTL bounds how long a crashed replica's per-tenant check
// lease blocks the others; a live holder renews it every third of it.
const easmDNSLeaseTTL = 10 * time.Minute

// TryLockTenant serializes one check kind for one tenant across API
// replicas with the controller lease "easm_dns:<tenant>:<kind>" (RFC-046
// P1.8; it was a session advisory lock on a dedicated connection).
func (r *EASMDNSRepository) TryLockTenant(ctx context.Context, tenantID shared.ID, kind string) (func(), bool, error) {
	release, ok, err := tryLeaseLock(ctx, NewControllerLeaseRepository(r.db), "easm_dns:"+tenantID.String()+":"+kind, easmDNSLeaseTTL)
	if err != nil {
		return nil, false, fmt.Errorf("easm dns lock: %w", err)
	}
	return release, ok, nil
}

var _ easmdns.TakeoverStore = (*EASMDNSRepository)(nil)

// OpenDanglingCNAMEs returns the tenant's active dangling_cname exposures
// raised by the DNS check on the given assets.
func (r *EASMDNSRepository) OpenDanglingCNAMEs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]easmdns.OpenDangling, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, asset_id, COALESCE(details->>'domain', ''), COALESCE(details->>'target', ''), COALESCE(details->>'provider', '')
		FROM exposure_events
		WHERE tenant_id = $1 AND source = $2 AND event_type = 'dangling_cname' AND state = 'active'
		  AND asset_id = ANY($3::uuid[])`,
		tenantID.String(), easmdns.Source, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("list open dangling CNAMEs: %w", err)
	}
	defer rows.Close()
	var out []easmdns.OpenDangling
	for rows.Next() {
		var (
			d       easmdns.OpenDangling
			assetID string
		)
		if err := rows.Scan(&d.ExposureID, &assetID, &d.Name, &d.Target, &d.Provider); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(assetID)
		if err != nil {
			continue
		}
		d.AssetID = id
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkConfirmed records on the tenant's exposures that a sensor confirmed
// them: details.confirmation = "confirmed" plus the evidence keys.
func (r *EASMDNSRepository) MarkConfirmed(ctx context.Context, tenantID shared.ID, exposureIDs []string, evidence map[string]any) error {
	if len(exposureIDs) == 0 {
		return nil
	}
	patch := map[string]any{"confirmation": "confirmed"}
	for k, v := range evidence {
		patch[k] = v
	}
	b, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("encode confirmation: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, `
		UPDATE exposure_events SET details = COALESCE(details, '{}'::jsonb) || $3::jsonb, updated_at = now()
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(exposureIDs), string(b)); err != nil {
		return fmt.Errorf("mark exposures confirmed: %w", err)
	}
	return nil
}
