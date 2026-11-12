package postgres

// Claim balance reads (docs/architecture/placement.md, "Spreading work
// across sensors"): which fresh jobs a claiming sensor shares with the other
// sensors of its organization, and each sensor's load. Read-only; the claim
// itself (ClaimManyForSensor) stays the authority.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// claimPeerSQL selects the sensors of tenant $1 that a claim may leave work
// to: organization sensors (never a shared one, never another tenant's),
// active and reachable, other than the claimer $2.
const claimPeerSQL = `sensors p
		WHERE p.tenant_id = $1 AND p.id <> $2
		  AND p.scope = 'organization'
		  AND p.status = 'active'
		  AND p.health IN ` + sensorDispatchableHealthSQL

// sensorLoadColumnsSQL is the load of the sensor aliased alias: free slots
// (the dispatch rule, sensorFreeSlotsSQL), its job limit (at least 1) and
// the commands it claimed in the last $recentParam seconds.
func sensorLoadColumnsSQL(alias, recentParam string) string {
	return sensorFreeSlotsSQL(alias) + ` AS free,
		GREATEST(COALESCE(` + alias + `.effective_max_jobs, 0), 1) AS total,
		(SELECT count(*) FROM commands rc
		  WHERE rc.tenant_id = ` + alias + `.tenant_id AND rc.sensor_id = ` + alias + `.id
		    AND rc.acknowledged_at > NOW() - make_interval(secs => ` + recentParam + `))::int AS recent`
}

// claimableSinceSQL is when a pending command became claimable: its
// creation, or the time a re-queue or a scan window deferred it to.
const claimableSinceSQL = `GREATEST(commands.created_at, COALESCE(commands.scheduled_at, commands.created_at))`

// ClaimContest implements command.ClaimContester.
func (r *CommandRepository) ClaimContest(ctx context.Context, tenantID, sensorID shared.ID, capabilities []string,
	window time.Duration, limit int,
) (command.ClaimContest, error) {
	out := command.ClaimContest{Peers: map[shared.ID]command.SensorLoad{}}
	if window <= 0 || limit <= 0 {
		return out, nil
	}
	recent := command.ClaimBalanceRecent.Seconds()
	// Fresh unassigned scan commands the claimer may take (the poll's
	// predicates for $2), each with the peers that may take it too and
	// have a free slot. Commands no peer can take are left out.
	query := `
		WITH peers AS (
			SELECT p.id, p.effective_capabilities, ` + sensorLoadColumnsSQL("p", "$6") + `
			FROM ` + claimPeerSQL + `
		)
		SELECT c.id, c.peers FROM (
			SELECT commands.id, commands.created_at,
				ARRAY(
					SELECT pr.id FROM peers pr
					WHERE pr.free > 0
					  AND ` + zoneClaimPredicate("pr.id") + `
					  AND ` + toolClaimPredicate("pr.id") + `
					  AND ` + refusedByPredicate("pr.id") + `
					  AND ` + featureClaimPredicate("pr.id") + `
					  AND ` + capabilityClaimPredicate("pr.effective_capabilities") + `
					ORDER BY pr.id) AS peers
			FROM commands
			WHERE commands.tenant_id = $1 AND commands.sensor_id IS NULL
			  AND commands.type = 'scan'
			  AND ` + claimableSinceSQL + ` > NOW() - make_interval(secs => $4)
			  AND ` + pendingReadyPredicate + `
			  AND ` + zoneClaimPredicate("$2") + `
			  AND ` + toolClaimPredicate("$2") + `
			  AND ` + refusedByPredicate("$2") + `
			  AND ` + featureClaimPredicate("$2") + `
			  AND ` + capabilityClaimPredicate("$3") + `
			ORDER BY commands.created_at, commands.id
			LIMIT $5
		) c
		WHERE cardinality(c.peers) > 0
		ORDER BY c.created_at, c.id`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), sensorID.String(), pq.Array(capabilities),
		window.Seconds(), limit, recent)
	if err != nil {
		return out, fmt.Errorf("failed to read the claim contest: %w", err)
	}
	defer rows.Close()
	seen := map[shared.ID]bool{}
	var peerIDs []shared.ID
	for rows.Next() {
		var id string
		var peers []string
		if err := rows.Scan(&id, pq.Array(&peers)); err != nil {
			return out, fmt.Errorf("failed to scan the claim contest: %w", err)
		}
		cid, err := shared.IDFromString(id)
		if err != nil {
			return out, fmt.Errorf("claim contest command id: %w", err)
		}
		cc := command.ContestedCommand{ID: cid, Peers: make([]shared.ID, 0, len(peers))}
		for _, p := range peers {
			pid, err := shared.IDFromString(p)
			if err != nil {
				return out, fmt.Errorf("claim contest sensor id: %w", err)
			}
			cc.Peers = append(cc.Peers, pid)
			if !seen[pid] {
				seen[pid] = true
				peerIDs = append(peerIDs, pid)
			}
		}
		out.Commands = append(out.Commands, cc)
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("failed to read the claim contest: %w", err)
	}
	if len(out.Commands) == 0 {
		return out, nil
	}
	loads, err := r.SensorLoads(ctx, tenantID, append(peerIDs, sensorID))
	if err != nil {
		return out, err
	}
	out.SelfRecent = loads[sensorID].Recent
	for _, id := range peerIDs {
		out.Peers[id] = loads[id]
	}
	return out, nil
}

// SensorLoads implements command.ClaimContester.
func (r *CommandRepository) SensorLoads(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]command.SensorLoad, error) {
	out := make(map[shared.ID]command.SensorLoad, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.id, `+sensorLoadColumnsSQL("s", "$3")+`
		FROM sensors s
		WHERE s.tenant_id = $1 AND s.id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(strs), command.ClaimBalanceRecent.Seconds())
	if err != nil {
		return nil, fmt.Errorf("failed to read sensor loads: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var l command.SensorLoad
		if err := rows.Scan(&id, &l.Free, &l.Total, &l.Recent); err != nil {
			return nil, fmt.Errorf("failed to scan sensor load: %w", err)
		}
		sid, err := shared.IDFromString(id)
		if err != nil {
			return nil, fmt.Errorf("sensor load id: %w", err)
		}
		out[sid] = l
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read sensor loads: %w", err)
	}
	return out, nil
}

// capToFreeSlots keeps, of the command ids a sensor is about to claim (in
// claim order), every command that is not a scan and no more scans than
// the sensor's free slots: its effective job limit (at least 1) minus the
// scans it holds, counted inside the claim's transaction. Claims by the
// same sensor are serialized on a transaction advisory lock (a heartbeat
// writing the sensor row is not blocked), so two claims racing on one
// sensor (a poll and a stream wake, two API replicas) cannot both see the
// same free slots and together exceed its limit.
func capToFreeSlots(ctx context.Context, tx *sql.Tx, tenantID, sensorID shared.ID, want []string) ([]string, error) {
	if len(want) == 0 {
		return want, nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('sensor-claim:' || $1::text, 0))`,
		sensorID.String()); err != nil {
		return nil, fmt.Errorf("failed to lock the sensor's claim: %w", err)
	}
	var free int
	err := tx.QueryRowContext(ctx, `
		SELECT GREATEST(COALESCE(s.effective_max_jobs, 0), 1) - (
			SELECT count(*) FROM commands h
			WHERE h.tenant_id = $1 AND h.sensor_id = s.id AND h.type = 'scan'
			  AND h.status IN ('acknowledged', 'running'))
		FROM sensors s WHERE s.id = $2 AND s.tenant_id = $1`,
		tenantID.String(), sensorID.String()).Scan(&free)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil // not a sensor of this tenant: nothing to claim
	}
	if err != nil {
		return nil, fmt.Errorf("failed to count the sensor's free slots: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, type = 'scan' FROM commands WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(want))
	if err != nil {
		return nil, fmt.Errorf("failed to read the claimed commands' types: %w", err)
	}
	defer rows.Close()
	scan := make(map[string]bool, len(want))
	for rows.Next() {
		var id string
		var isScan bool
		if err := rows.Scan(&id, &isScan); err != nil {
			return nil, fmt.Errorf("failed to read the claimed commands' types: %w", err)
		}
		scan[id] = isScan
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read the claimed commands' types: %w", err)
	}
	out := want[:0:0]
	for _, id := range want {
		if scan[id] {
			if free <= 0 {
				continue
			}
			free--
		}
		out = append(out, id)
	}
	return out, nil
}
