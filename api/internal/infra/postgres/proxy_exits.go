package postgres

// Scanner addresses (docs/architecture/sensor-proxies.md, "Scanner
// addresses"): the addresses the platform's proxy-test echo saw, the exit
// addresses of endpoints verified against them, and the addresses the
// platform saw the tenant's own sensors connect from. Every statement is
// tenant-scoped; an exit names an endpoint of the tenant's pool through a
// composite (tenant_id, pool_id, endpoint_id) key.

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ proxypool.ExitStore = (*ProxyPoolRepository)(nil)

// maxExitRows bounds the exits and sensor addresses one list reads.
const maxExitRows = 2000

// RecordEchoObservation stores an address the echo answered for a
// proxy_test command of the tenant, at most
// proxypool.MaxEchoObservationsPerTest per command.
func (r *ProxyPoolRepository) RecordEchoObservation(ctx context.Context, tenantID, commandID shared.ID, addr netip.Addr, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO proxy_echo_observations (tenant_id, command_id, address, observed_at)
		SELECT c.tenant_id, c.id, $3::inet, $4
		  FROM commands c
		 WHERE c.tenant_id = $1 AND c.id = $2 AND c.type = 'proxy_test'
		   AND (SELECT count(*) FROM proxy_echo_observations o
		         WHERE o.tenant_id = $1 AND o.command_id = $2) < $5
		ON CONFLICT (tenant_id, command_id, address) DO UPDATE SET observed_at = EXCLUDED.observed_at`,
		tenantID.String(), commandID.String(), addr.Unmap().String(), at, proxypool.MaxEchoObservationsPerTest)
	if err != nil {
		return fmt.Errorf("record proxy echo observation: %w", err)
	}
	return nil
}

// EchoObservations returns the addresses the echo answered for a command.
func (r *ProxyPoolRepository) EchoObservations(ctx context.Context, tenantID, commandID shared.ID) ([]netip.Addr, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT host(address) FROM proxy_echo_observations
		 WHERE tenant_id = $1 AND command_id = $2
		 LIMIT $3`, tenantID.String(), commandID.String(), proxypool.MaxEchoObservationsPerTest)
	if err != nil {
		return nil, fmt.Errorf("read proxy echo observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []netip.Addr{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan proxy echo observation: %w", err)
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out, rows.Err()
}

// RecordEndpointExits stores verified exit addresses of endpoints of a pool,
// then removes the command's observations, stale observations of the tenant
// and exits not seen within twice the retention.
func (r *ProxyPoolRepository) RecordEndpointExits(ctx context.Context, tenantID, poolID, commandID shared.ID,
	exits []proxypool.EndpointExit, at time.Time,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin record exits: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, e := range exits {
		// The endpoint must be the pool's and the pool the tenant's: the
		// SELECT finds nothing otherwise, and nothing is stored.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO proxy_endpoint_exits (tenant_id, pool_id, endpoint_id, address, first_seen_at, last_seen_at)
			SELECT e.tenant_id, e.pool_id, e.id, $4::inet, $5, $5
			  FROM proxy_endpoints e
			 WHERE e.tenant_id = $1 AND e.pool_id = $2 AND e.id = $3
			ON CONFLICT (tenant_id, endpoint_id, address) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at`,
			tenantID.String(), poolID.String(), e.EndpointID.String(), e.Address.Unmap().String(), at); err != nil {
			return fmt.Errorf("record proxy endpoint exit: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM proxy_echo_observations
		 WHERE tenant_id = $1 AND (command_id = $2 OR observed_at < $3)`,
		tenantID.String(), commandID.String(), at.Add(-proxypool.EchoObservationTTL)); err != nil {
		return fmt.Errorf("remove proxy echo observations: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM proxy_endpoint_exits WHERE tenant_id = $1 AND pool_id = $2 AND last_seen_at < $3`,
		tenantID.String(), poolID.String(), at.Add(-2*proxypool.ExitRetention)); err != nil {
		return fmt.Errorf("prune proxy endpoint exits: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit record exits: %w", err)
	}
	return nil
}

// ListEndpointExits returns the tenant's exit addresses last seen since a
// time, newest first.
func (r *ProxyPoolRepository) ListEndpointExits(ctx context.Context, tenantID shared.ID, since time.Time) ([]proxypool.ExitRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT x.pool_id, p.name, x.endpoint_id, e.label, host(x.address), x.first_seen_at, x.last_seen_at
		  FROM proxy_endpoint_exits x
		  JOIN proxy_pools p ON p.tenant_id = x.tenant_id AND p.id = x.pool_id
		  JOIN proxy_endpoints e ON e.tenant_id = x.tenant_id AND e.pool_id = x.pool_id AND e.id = x.endpoint_id
		 WHERE x.tenant_id = $1 AND x.last_seen_at >= $2
		 ORDER BY x.last_seen_at DESC, x.address
		 LIMIT $3`, tenantID.String(), since, maxExitRows)
	if err != nil {
		return nil, fmt.Errorf("list proxy endpoint exits: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []proxypool.ExitRow{}
	for rows.Next() {
		var (
			x           proxypool.ExitRow
			pool, ep, a string
		)
		if err := rows.Scan(&pool, &x.PoolName, &ep, &x.EndpointLabel, &a, &x.FirstSeenAt, &x.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan proxy endpoint exit: %w", err)
		}
		addr, err := netip.ParseAddr(a)
		if err != nil {
			continue
		}
		x.PoolID, x.EndpointID, x.Address = shared.MustIDFromString(pool), shared.MustIDFromString(ep), addr.Unmap()
		out = append(out, x)
	}
	return out, rows.Err()
}

// ListSensorEgress returns the addresses the platform saw the tenant's own
// active sensors connect from: the heartbeat's client address and the last
// authenticated request's, both resolved with the trusted-proxy rule (never
// a value the sensor sends). Shared sensors are never listed.
func (r *ProxyPoolRepository) ListSensorEgress(ctx context.Context, tenantID shared.ID, since time.Time) ([]proxypool.SensorEgressRow, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.id, s.name, host(a.addr), s.last_seen_at
		  FROM sensors s
		 CROSS JOIN LATERAL (VALUES (s.ip_address), (s.api_key_last_used_ip)) AS a(addr)
		 WHERE s.tenant_id = $1 AND s.scope = 'organization' AND s.status = 'active'
		   AND a.addr IS NOT NULL
		   AND COALESCE(s.last_seen_at, s.api_key_last_used_at) >= $2
		 GROUP BY s.id, s.name, a.addr, s.last_seen_at
		 ORDER BY s.name, host(a.addr)
		 LIMIT $3`, tenantID.String(), since, maxExitRows)
	if err != nil {
		return nil, fmt.Errorf("list sensor egress: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []proxypool.SensorEgressRow{}
	for rows.Next() {
		var (
			x      proxypool.SensorEgressRow
			id, a  string
			seenAt sql.NullTime
		)
		if err := rows.Scan(&id, &x.SensorName, &a, &seenAt); err != nil {
			return nil, fmt.Errorf("scan sensor egress: %w", err)
		}
		addr, err := netip.ParseAddr(a)
		if err != nil {
			continue
		}
		x.SensorID, x.Address = shared.MustIDFromString(id), addr.Unmap()
		if seenAt.Valid {
			t := seenAt.Time
			x.LastSeenAt = &t
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
