package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// Platform-wide counts for the operator's metrics (docs/operations/monitoring.md).
//
// These are deliberately NOT tenant-scoped: they are aggregate counts of the
// platform's own machinery (queues, sensors, schema) read by the operator's
// monitoring, never served to a tenant. No row content leaves this file: the
// snapshot holds counts, ages and the coarse states the alerts need. Every
// query is an aggregate over an indexed status column.

// OpsSensorCount is the number of active sensors with one combination of
// kind, health, configuration health and SDK version.
type OpsSensorCount struct {
	Platform     bool
	Health       string
	ConfigHealth string
	SDKVersion   string
	Count        int64
}

// OpsSnapshot is one read of the platform-wide counts.
type OpsSnapshot struct {
	Sensors []OpsSensorCount

	// SensorsUnhardened counts active tenant sensors by unhardened reason
	// (sensor.UnhardenedKinds: policy_none, pin_none, network_unenforced,
	// bearer_key). A sensor with several reasons counts under each.
	SensorsUnhardened map[string]int64

	// Commands waiting for a sensor (pending and due) and held by one
	// (acknowledged or running), and how long the oldest due pending
	// command has waited, in seconds (0 when none).
	CommandsPending          int64
	CommandsRunning          int64
	CommandOldestPendingSecs float64

	// Scan runs not finished, and those of them more than 10 minutes past
	// their deadline (the timeout controller reaps on its own tick, so a
	// run that stays past it means the reaper is not running).
	ScanRunsOpen         int64
	ScanRunsPastDeadline int64

	// Notification outbox entries by state, and the age of the oldest due
	// pending entry in seconds (0 when none).
	OutboxPending          int64
	OutboxFailed           int64
	OutboxDead             int64
	OutboxOldestPendingSec float64

	// The newest applied migration (golang-migrate's single row) and
	// whether it is dirty. SchemaKnown is false when the table is empty.
	SchemaVersion int64
	SchemaDirty   bool
	SchemaKnown   bool
}

// opsQuerier is a *sql.DB or a *sql.Tx: the snapshot reads within one
// transaction when given one (its tests read before and after their own
// writes, isolated from other tests).
type opsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ReadOpsSnapshot reads the platform-wide counts.
func ReadOpsSnapshot(ctx context.Context, db opsQuerier) (OpsSnapshot, error) {
	var s OpsSnapshot

	sensors, err := readOpsSensors(ctx, db)
	if err != nil {
		return s, fmt.Errorf("sensors: %w", err)
	}
	s.Sensors = sensors

	unhardened, err := readOpsUnhardened(ctx, db)
	if err != nil {
		return s, fmt.Errorf("unhardened sensors: %w", err)
	}
	s.SensorsUnhardened = unhardened

	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE status = 'pending' AND COALESCE(scheduled_at, created_at) <= now()),
		       count(*) FILTER (WHERE status IN ('acknowledged', 'running')),
		       COALESCE(EXTRACT(EPOCH FROM now() - min(COALESCE(scheduled_at, created_at))
		                FILTER (WHERE status = 'pending' AND COALESCE(scheduled_at, created_at) <= now())), 0)
		FROM commands
		WHERE status IN ('pending', 'acknowledged', 'running')`,
	).Scan(&s.CommandsPending, &s.CommandsRunning, &s.CommandOldestPendingSecs); err != nil {
		return s, fmt.Errorf("commands: %w", err)
	}

	if err := db.QueryRowContext(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE deadline_at IS NOT NULL AND deadline_at < now() - interval '10 minutes')
		FROM scan_runs
		WHERE status IN ('pending', 'running')`,
	).Scan(&s.ScanRunsOpen, &s.ScanRunsPastDeadline); err != nil {
		return s, fmt.Errorf("scan runs: %w", err)
	}

	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE status = 'pending'),
		       count(*) FILTER (WHERE status = 'failed'),
		       count(*) FILTER (WHERE status = 'dead'),
		       COALESCE(EXTRACT(EPOCH FROM now() - min(scheduled_at)
		                FILTER (WHERE status = 'pending' AND scheduled_at <= now())), 0)
		FROM notification_outbox
		WHERE status IN ('pending', 'failed', 'dead')`,
	).Scan(&s.OutboxPending, &s.OutboxFailed, &s.OutboxDead, &s.OutboxOldestPendingSec); err != nil {
		return s, fmt.Errorf("outbox: %w", err)
	}

	err = db.QueryRowContext(ctx,
		`SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 1`,
	).Scan(&s.SchemaVersion, &s.SchemaDirty)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return s, fmt.Errorf("schema version: %w", err)
	default:
		s.SchemaKnown = true
	}

	return s, nil
}

func readOpsSensors(ctx context.Context, db opsQuerier) ([]OpsSensorCount, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT is_platform_sensor, COALESCE(health, 'unknown'), COALESCE(config_health, ''),
		       COALESCE(sdk_version, ''), count(*)
		FROM sensors
		WHERE status = 'active'
		GROUP BY 1, 2, 3, 4`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []OpsSensorCount
	for rows.Next() {
		var c OpsSensorCount
		if err := rows.Scan(&c.Platform, &c.Health, &c.ConfigHealth, &c.SDKVersion, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// readOpsUnhardened counts active tenant sensors by unhardened reason. The
// rows are grouped by the few values the posture is derived from (the local
// policy state and requirement, the current manifest's platform TLS pin and
// sandbox network confinement, the auth kind, whether the sensor has
// connected), and sensor.DerivePosture judges each group, so the gauge and
// the console flag the same sensors.
func readOpsUnhardened(ctx context.Context, db opsQuerier) (map[string]int64, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT s.reported_local_policy->>'state', COALESCE(s.reported_local_policy->>'required', 'false') = 'true',
		       p.posture->'platform_tls'->>'pin', p.posture->'sandbox'->>'network_enforced',
		       COALESCE(s.auth_kind, '') = '`+string(sensor.AuthKindKeyBound)+`', s.last_seen_at IS NOT NULL, count(*)
		FROM sensors s
		LEFT JOIN LATERAL (SELECT `+sensorManifestPostureSQL("s")+` AS posture) p ON TRUE
		WHERE s.status = 'active' AND NOT s.is_platform_sensor
		GROUP BY 1, 2, 3, 4, 5, 6`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]int64, len(sensor.UnhardenedKinds()))
	for _, k := range sensor.UnhardenedKinds() {
		out[k] = 0
	}
	for rows.Next() {
		var (
			state, pin, netEnforced  sql.NullString
			required, keyBound, seen bool
			n                        int64
		)
		if err := rows.Scan(&state, &required, &pin, &netEnforced, &keyBound, &seen, &n); err != nil {
			return nil, err
		}
		in := sensor.PostureInput{KeyBound: keyBound, Seen: seen}
		if state.Valid {
			in.LocalPolicy = &sensor.LocalPolicyReport{State: state.String, Required: required}
		}
		if pin.Valid || netEnforced.Valid {
			in.Posture = &sensor.ManifestPosture{}
			if pin.Valid {
				in.Posture.PlatformTLS = &sensor.PlatformTLSPosture{Pin: pin.String}
			}
			if netEnforced.Valid {
				in.Posture.Sandbox = &sensor.SandboxPosture{NetworkEnforced: netEnforced.String == "true"}
			}
		}
		for _, reason := range sensor.DerivePosture(in).Unhardened {
			out[reason] += n
		}
	}
	return out, rows.Err()
}
