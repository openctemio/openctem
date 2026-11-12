package postgres

// Locations of version-match findings (softwarematch.LocationStore;
// docs/architecture/vulnerability-matching.md, "Locations").
//
// Every statement is scoped to one tenant. The table's foreign keys
// reference findings and assets by (id, tenant_id), so a location can never
// name another tenant's finding or asset.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/softwarematch"
)

var _ softwarematch.LocationStore = (*SoftwareMatchRepository)(nil)

// Keys of the timeline changes and audit metadata of location writes and the
// location merge.
const (
	locKeyReason   = "reason"
	locKeyAssetID  = "asset_id"
	locKeySource   = "source"
	locKeyLocation = "location"
	locKeyDupOf    = "duplicate_of"
	locKeyLoserID  = "loser_id"
	locKeyRunID    = "run_id"
	locKeySurvivor = "survivor_id"
)

// locationColumns are the columns readLocations scans.
const locationColumns = `l.id, l.finding_id, l.asset_id, l.location_key, l.port, l.transport,
	l.product_id::text, l.version_id::text, l.version, l.link_location, l.evidence,
	l.state, l.state_reason, l.state_at, l.first_seen_at, l.last_seen_at, a.name`

// TenantLocations (see softwarematch.LocationStore).
func (r *SoftwareMatchRepository) TenantLocations(ctx context.Context, tenantID shared.ID) ([]softwarematch.Location, error) {
	return readLocations(ctx, r.db, `SELECT `+locationColumns+`
		FROM finding_locations l
		JOIN assets a ON a.id = l.asset_id AND a.tenant_id = l.tenant_id
		WHERE l.tenant_id = $1
		ORDER BY l.finding_id, l.port, l.location_key
		LIMIT 200000`, tenantID.String())
}

// FindingLocations returns the locations of one finding of the tenant,
// ordered by port.
func (r *SoftwareMatchRepository) FindingLocations(ctx context.Context, tenantID, findingID shared.ID) ([]softwarematch.Location, error) {
	return readLocations(ctx, r.db, `SELECT `+locationColumns+`
		FROM finding_locations l
		JOIN assets a ON a.id = l.asset_id AND a.tenant_id = l.tenant_id
		WHERE l.tenant_id = $1 AND l.finding_id = $2
		ORDER BY l.port, l.location_key
		LIMIT 1000`, tenantID.String(), findingID.String())
}

type locationQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func readLocations(ctx context.Context, q locationQueryer, query string, args ...any) ([]softwarematch.Location, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("finding locations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []softwarematch.Location
	for rows.Next() {
		var l softwarematch.Location
		var id, fid, aid, state string
		var pid, vid sql.NullString
		if err := rows.Scan(&id, &fid, &aid, &l.Key, &l.Port, &l.Transport, &pid, &vid, &l.Version, &l.LinkLocation,
			&l.Evidence, &state, &l.StateReason, &l.StateAt, &l.FirstSeen, &l.LastSeen, &l.AssetName); err != nil {
			return nil, fmt.Errorf("finding locations: %w", err)
		}
		l.ID, l.FindingID, l.AssetID = shared.MustIDFromString(id), shared.MustIDFromString(fid), shared.MustIDFromString(aid)
		l.State = softwarematch.LocationState(state)
		if p, err := shared.IDFromString(pid.String); pid.Valid && err == nil {
			l.ProductID = &p
		}
		if v, err := shared.IDFromString(vid.String); vid.Valid && err == nil {
			l.VersionID = &v
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// locationEvent is one timeline entry and audit row of a location write.
type locationEvent struct {
	findingID, assetID, label, from, to, reason, version string
}

// WriteLocations (see softwarematch.LocationStore). All writes of one call
// run in one transaction; the audit rows go last (the audit chain takes a
// per-tenant lock, every other writer locks its business rows first).
func (r *SoftwareMatchRepository) WriteLocations(ctx context.Context, tenantID shared.ID, writes []softwarematch.LocationWrite) (int, error) {
	if len(writes) == 0 {
		return 0, nil
	}
	tenant := tenantID.String()
	n := 0
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var events []locationEvent
		for _, w := range writes {
			ev, changed, err := writeLocation(ctx, tx, tenant, w)
			if err != nil {
				return err
			}
			if changed {
				n++
			}
			if ev != nil {
				events = append(events, *ev)
			}
		}
		return recordLocationEvents(ctx, tx, tenant, events, vulnmatchSource, "system: software vulnerability matcher")
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// writeLocation applies one write. It returns the event to record (nil for
// none) and whether a row changed.
func writeLocation(ctx context.Context, tx *sql.Tx, tenant string, w softwarematch.LocationWrite) (*locationEvent, bool, error) {
	if w.Key == "" || w.FindingID.IsZero() || w.AssetID.IsZero() {
		return nil, false, nil
	}
	var curFinding, curState string
	err := tx.QueryRowContext(ctx, `SELECT finding_id::text, state FROM finding_locations
		WHERE tenant_id = $1 AND location_key = $2 FOR UPDATE`, tenant, w.Key).Scan(&curFinding, &curState)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if !w.Seen {
			return nil, false, nil
		}
		return insertLocation(ctx, tx, tenant, w)
	case err != nil:
		return nil, false, fmt.Errorf("read finding location: %w", err)
	case curFinding != w.FindingID.String():
		// The location belongs to another finding.
		return nil, false, nil
	}
	if w.Seen {
		// A sighting: the vulnerable version is observed here now.
		if _, err := tx.ExecContext(ctx, `UPDATE finding_locations SET
				asset_id = $3, port = $4, transport = $5, product_id = $6, version_id = $7, version = $8,
				link_location = $9, evidence = $10, last_seen_at = now(), updated_at = now(),
				state = 'affected',
				state_reason = CASE WHEN state = 'affected' THEN state_reason ELSE $11 END,
				state_at = CASE WHEN state = 'affected' THEN state_at ELSE now() END
			WHERE tenant_id = $1 AND location_key = $2`,
			tenant, w.Key, w.AssetID.String(), w.Port, w.Transport, idOrNil(w.ProductID), idOrNil(w.VersionID),
			clipText(w.Version, 128), clipText(w.LinkLocation, 512), softwarematch.LocationEvidence(w.Evidence),
			softwarematch.ReasonMatchedAgain); err != nil {
			return nil, false, fmt.Errorf("update finding location: %w", err)
		}
		if curState == string(softwarematch.LocationAffected) {
			return nil, true, nil
		}
		return &locationEvent{findingID: w.FindingID.String(), assetID: w.AssetID.String(), label: w.Label,
			from: curState, to: string(softwarematch.LocationAffected), reason: softwarematch.ReasonMatchedAgain, version: w.Version}, true, nil
	}
	if curState != string(w.From) || w.State == w.From {
		return nil, false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE finding_locations SET state = $3, state_reason = $4, state_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND location_key = $2 AND state = $5`,
		tenant, w.Key, string(w.State), clipText(w.Reason, 32), string(w.From)); err != nil {
		return nil, false, fmt.Errorf("move finding location: %w", err)
	}
	return &locationEvent{findingID: w.FindingID.String(), assetID: w.AssetID.String(), label: w.Label,
		from: curState, to: string(w.State), reason: w.Reason, version: w.Version}, true, nil
}

func insertLocation(ctx context.Context, tx *sql.Tx, tenant string, w softwarematch.LocationWrite) (*locationEvent, bool, error) {
	// Only a live (not duplicate) finding of the tenant gets a location; the
	// asset is checked by the foreign key (tenant_id, asset_id).
	res, err := tx.ExecContext(ctx, `INSERT INTO finding_locations (tenant_id, finding_id, asset_id, location_key, port, transport,
			product_id, version_id, version, link_location, evidence, state, state_reason)
		SELECT $1, f.id, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'affected', $12
		FROM findings f WHERE f.tenant_id = $1 AND f.id = $2 AND f.status <> 'duplicate'
		ON CONFLICT (tenant_id, location_key) DO NOTHING`,
		tenant, w.FindingID.String(), w.AssetID.String(), w.Key, w.Port, w.Transport, idOrNil(w.ProductID), idOrNil(w.VersionID),
		clipText(w.Version, 128), clipText(w.LinkLocation, 512), softwarematch.LocationEvidence(w.Evidence), softwarematch.ReasonObserved)
	if err != nil {
		return nil, false, fmt.Errorf("insert finding location: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, false, nil
	}
	if w.Quiet {
		return nil, true, nil
	}
	return &locationEvent{findingID: w.FindingID.String(), assetID: w.AssetID.String(), label: w.Label,
		to: string(softwarematch.LocationAffected), reason: softwarematch.ReasonObserved, version: w.Version}, true, nil
}

// recordLocationEvents writes one timeline entry per event and then one
// audit row per event. The timeline names the service by scheme and port
// only (never the asset), so it shows nothing about another asset beyond
// that its host answers there; the audit row names the asset.
func recordLocationEvents(ctx context.Context, tx *sql.Tx, tenant string, events []locationEvent, source, actorName string) error {
	for _, e := range events {
		changes, _ := json.Marshal(map[string]string{locKeyLocation: e.label, "from_state": e.from, "to_state": e.to,
			locKeyReason: e.reason, "version": e.version, "actor_name": actorName})
		if _, err := tx.ExecContext(ctx, `INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, changes, source, message)
			VALUES ($1, $2, 'location_changed', 'system', $3, $4, $5)`,
			tenant, e.findingID, changes, source, locationMessage(e)); err != nil {
			return fmt.Errorf("record location timeline: %w", err)
		}
	}
	for _, e := range events {
		meta, _ := json.Marshal(map[string]string{locKeyAssetID: e.assetID, locKeyLocation: e.label, "from_state": e.from,
			"to_state": e.to, locKeyReason: e.reason, locKeySource: source})
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, metadata, logged_at)
			VALUES (gen_random_uuid(), $1, $2, 'finding', $3, 'success', 'low', $4, $5::jsonb, NOW())`,
			tenant, string(audit.ActionFindingLocationChanged), e.findingID, locationMessage(e), string(meta)); err != nil {
			return fmt.Errorf("audit location change: %w", err)
		}
	}
	return nil
}

func locationMessage(e locationEvent) string {
	switch {
	case e.from == "":
		return "Affected on " + e.label + " as well"
	case e.to == string(softwarematch.LocationFixed):
		return "Fixed on " + e.label
	case e.to == string(softwarematch.LocationNotAffected):
		return "Not affected on " + e.label + " (the advisory changed)"
	default:
		return "Affected on " + e.label + " again"
	}
}

// ScopeSignatures (see softwarematch.LocationStore). Two assets with equal
// signatures have the same scope rows (user_accessible_assets) and the same
// program-only flag and private program links, so every scope rule
// (filterspec.ScopeSQL, NotHiddenSQL) answers alike for them, whoever asks.
func (r *SoftwareMatchRepository) ScopeSignatures(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]string, error) {
	return scopeSignatures(ctx, r.db, tenantID.String(), ids)
}

func scopeSignatures(ctx context.Context, q locationQueryer, tenant string, ids []shared.ID) (map[shared.ID]string, error) {
	out := make(map[shared.ID]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	rows, err := q.QueryContext(ctx, `
		SELECT a.id::text, md5(
			COALESCE((SELECT string_agg(DISTINCT u.user_id::text, ',' ORDER BY u.user_id::text) FROM user_accessible_assets u
			          WHERE u.tenant_id = a.tenant_id AND u.asset_id = a.id), '') || '|' ||
			COALESCE(a.program_only, false)::text || '|' ||
			COALESCE((SELECT string_agg(DISTINCT pl.program_id::text, ',' ORDER BY pl.program_id::text)
			          FROM asset_program_links pl
			          JOIN bounty_programs pp ON pp.tenant_id = pl.tenant_id AND pp.id = pl.program_id
			          WHERE pl.tenant_id = a.tenant_id AND pl.asset_id = a.id AND pp.visibility = 'private'), ''))
		FROM assets a
		WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])`, tenant, pq.Array(strs))
	if err != nil {
		return nil, fmt.Errorf("asset scope signatures: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, sig string
		if err := rows.Scan(&id, &sig); err != nil {
			return nil, fmt.Errorf("asset scope signatures: %w", err)
		}
		out[shared.MustIDFromString(id)] = sig
	}
	return out, rows.Err()
}

func idOrNil(id shared.ID) any {
	if id.IsZero() {
		return nil
	}
	return id.String()
}
