package postgres

// Host keys and host counts for emerging-threat alerts planned before an
// alert counted hosts (docs/architecture/emerging-threat-alerts.md, "Counting
// hosts"). The planner writes both on every plan; this fills the alerts it
// has not planned since.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
)

const (
	// threatAlertHostsBatch bounds the alerts one backfill transaction
	// reads and writes.
	threatAlertHostsBatch = 100
	// threatAlertHostsTimeout bounds each statement of a batch.
	threatAlertHostsTimeout = 30 * time.Second
	// threatAlertHostsPasses bounds the passes over the table: a later pass
	// takes the alerts a triage decision or the planner changed while an
	// earlier one read them.
	threatAlertHostsPasses = 3
	// threatAlertHostsLock is the advisory lock one runner holds per batch.
	threatAlertHostsLock = "threat_alert_hosts_backfill"
)

// BackfillThreatAlertHosts gives every alert asset without a host key its
// key (threatalert.HostKey) and recomputes the stored host counts of those
// alerts (threatalert.CountHosts), in batches of threatAlertHostsBatch
// alerts, one short transaction each. Nothing else of an alert changes: not
// its score, level, state, delivery marks or updated_at, so nothing is sent
// again and the list keeps its order.
//
// Idempotent: a row with a key is never read again, and a second run finds
// nothing. Safe beside the planner and triage: an alert that changed after
// the batch read it is left for the next pass (the planner writes keys and
// counts itself). One replica runs at a time (advisory lock); the others
// return at once. Returns the alerts updated.
func BackfillThreatAlertHosts(ctx context.Context, db *sql.DB) (int, error) {
	total := 0
	for pass := 0; pass < threatAlertHostsPasses; pass++ {
		updated, skipped, err := backfillThreatAlertHostsPass(ctx, db)
		total += updated
		if err != nil || skipped == 0 || updated == 0 {
			return total, err
		}
	}
	return total, nil
}

// backfillThreatAlertHostsPass walks the alerts with keyless assets once, in
// id order, and reports the alerts updated and those left (changed meanwhile).
func backfillThreatAlertHostsPass(ctx context.Context, db *sql.DB) (updated, skipped int, err error) {
	cursor := uuidBeforeAll
	for {
		found, done, last, err := backfillThreatAlertHostsBatch(ctx, db, cursor)
		updated += done
		skipped += found - done
		if err != nil || found == 0 {
			return updated, skipped, err
		}
		cursor = last
	}
}

// alertHostsRow is one alert of a backfill batch.
type alertHostsRow struct {
	tenant    string
	updatedAt string
	assets    []threatalert.Asset
}

// backfillThreatAlertHostsBatch handles the next alerts after cursor. found
// is how many alerts it read (zero: nothing left, or another replica runs),
// done how many it updated, last the id to continue after.
func backfillThreatAlertHostsBatch(ctx context.Context, db *sql.DB, cursor string) (found, done int, last string, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, "", fmt.Errorf("backfill alert hosts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setLocalStatementTimeout(ctx, tx, threatAlertHostsTimeout); err != nil {
		return 0, 0, "", err
	}
	var mine bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtext($1))`, threatAlertHostsLock).Scan(&mine); err != nil {
		return 0, 0, "", fmt.Errorf("backfill alert hosts: %w", err)
	}
	if !mine {
		return 0, 0, "", nil
	}
	ids, err := alertHostStrings(ctx, tx, `
		SELECT DISTINCT alert_id FROM threat_alert_assets
		WHERE host_key = '' AND alert_id > $1::uuid
		ORDER BY alert_id LIMIT $2`, cursor, threatAlertHostsBatch)
	if err != nil || len(ids) == 0 {
		return 0, 0, "", err
	}
	alerts, err := readAlertHosts(ctx, tx, ids)
	if err != nil {
		return 0, 0, "", err
	}
	n := len(alerts)
	alertIDs, tenants, readAt := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
	conf, likely, poss, inet := make([]int64, 0, n), make([]int64, 0, n), make([]int64, 0, n), make([]int64, 0, n)
	for id, a := range alerts {
		c := threatalert.CountHosts(a.assets)
		alertIDs, tenants, readAt = append(alertIDs, id), append(tenants, a.tenant), append(readAt, a.updatedAt)
		conf, likely = append(conf, int64(c.Confirmed)), append(likely, int64(c.Likely))
		poss, inet = append(poss, int64(c.Possible)), append(inet, int64(c.InternetFacing))
	}
	// The counters first, and only of alerts unchanged since they were read:
	// the row lock then holds the planner off these alerts until the keys
	// below are written.
	counted, err := alertHostStrings(ctx, tx, `
		UPDATE threat_alerts ta
		SET confirmed_assets = x.c, likely_assets = x.l, possible_assets = x.p, internet_facing_assets = x.i
		FROM unnest($1::uuid[], $2::uuid[], $3::text[], $4::int[], $5::int[], $6::int[], $7::int[])
			AS x(id, tenant, read_at, c, l, p, i)
		WHERE ta.id = x.id AND ta.tenant_id = x.tenant AND ta.updated_at = x.read_at::timestamptz
		RETURNING ta.id::text`,
		pq.Array(alertIDs), pq.Array(tenants), pq.Array(readAt), pq.Array(conf), pq.Array(likely), pq.Array(poss), pq.Array(inet))
	if err != nil {
		return 0, 0, "", err
	}
	var kAlert, kTenant, kAsset, kKey []string
	for _, id := range counted {
		a := alerts[id]
		for _, x := range a.assets {
			kAlert, kTenant = append(kAlert, id), append(kTenant, a.tenant)
			kAsset, kKey = append(kAsset, x.AssetID.String()), append(kKey, threatalert.HostKey(x))
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE threat_alert_assets taa SET host_key = x.key
		FROM unnest($1::uuid[], $2::uuid[], $3::uuid[], $4::text[]) AS x(alert, tenant, asset, key)
		WHERE taa.alert_id = x.alert AND taa.asset_id = x.asset AND taa.tenant_id = x.tenant AND taa.host_key = ''`,
		pq.Array(kAlert), pq.Array(kTenant), pq.Array(kAsset), pq.Array(kKey)); err != nil {
		return 0, 0, "", fmt.Errorf("backfill alert hosts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, "", fmt.Errorf("backfill alert hosts: %w", err)
	}
	return len(ids), len(counted), ids[len(ids)-1], nil
}

// readAlertHosts reads the alerts and all their assets (name, tier,
// exposure, criticality: what the host counts need).
func readAlertHosts(ctx context.Context, tx *sql.Tx, ids []string) (map[string]*alertHostsRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT ta.id::text, ta.tenant_id::text, ta.updated_at::text, taa.asset_id, a.name, taa.match_kind,
			taa.internet_facing, taa.criticality
		FROM threat_alerts ta
		JOIN threat_alert_assets taa ON taa.tenant_id = ta.tenant_id AND taa.alert_id = ta.id
		JOIN assets a ON a.tenant_id = taa.tenant_id AND a.id = taa.asset_id
		WHERE ta.id = ANY($1::uuid[])`, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("backfill alert hosts: %w", err)
	}
	defer rows.Close()
	out := make(map[string]*alertHostsRow, len(ids))
	for rows.Next() {
		var id, tenant, updatedAt, kind string
		var x threatalert.Asset
		var asset shared.ID
		if err := rows.Scan(&id, &tenant, &updatedAt, &asset, &x.Name, &kind, &x.InternetFacing, &x.Criticality); err != nil {
			return nil, fmt.Errorf("backfill alert hosts: %w", err)
		}
		x.AssetID, x.Kind = asset, threatalert.MatchKind(kind)
		a := out[id]
		if a == nil {
			a = &alertHostsRow{tenant: tenant, updatedAt: updatedAt}
			out[id] = a
		}
		a.assets = append(a.assets, x)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backfill alert hosts: %w", err)
	}
	return out, nil
}

// alertHostStrings runs a statement that returns one text column.
func alertHostStrings(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("backfill alert hosts: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("backfill alert hosts: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backfill alert hosts: %w", err)
	}
	return out, nil
}
