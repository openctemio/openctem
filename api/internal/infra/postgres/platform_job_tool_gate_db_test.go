package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-030 B10: get_next_platform_job used to ignore p_tools and
// p_capabilities, so a platform sensor could claim a job for a tool it does
// not have. Requires DATABASE_URL (CI applies every migration first).
//
// Runs on a queue isolated from other tests (withIsolatedPlatformQueue): a
// tool-less pending platform job another test leaves behind matches the
// "no tools" claim below and used to be claimed instead of this test's job.
func TestGetNextPlatformJob_ToolAndCapabilityGates(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, db)
	sensorID := seedJobSensor(ctx, t, db, tenantID)

	withIsolatedPlatformQueue(ctx, t, db, []shared.ID{tenantID}, func(tx *sql.Tx) error {
		seed := func(payload string, priority int) shared.ID {
			t.Helper()
			id := shared.NewID()
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO commands (id, tenant_id, type, priority, payload, status, is_platform_job, queue_priority, queued_at)
				VALUES ($1, $2, 'scan', 'normal', $3::jsonb, 'pending', TRUE, $4, NOW())`,
				id.String(), tenantID.String(), payload, priority); err != nil {
				t.Fatalf("seed platform job: %v", err)
			}
			return id
		}
		// Descending queue priorities, so with no gates the nuclei job would
		// be claimed first.
		nuclei := seed(`{"scanner":"nuclei"}`, 4)
		step := seed(`{"preferred_tool":"trivy"}`, 3)
		needsInfra := seed(`{"required_capabilities":["infra"]}`, 2)
		plain := seed(`{"kind":"collect"}`, 1)

		claim := func(caps, tools []string) shared.ID {
			t.Helper()
			id, err := claimPlatformJobTx(ctx, tx, sensorID, caps, tools)
			if err != nil {
				t.Fatalf("get_next_platform_job: %v", err)
			}
			return id
		}

		// A sensor with no tools and no capabilities skips the nuclei job, the
		// trivy step and the infra job, and gets the plain one.
		if got := claim(nil, nil); got != plain {
			t.Fatalf("sensor without tools claimed %s; want the tool-less job %s", got, plain)
		}
		// betterleaks only: none of the gated jobs, and the plain one is taken.
		if got := claim(nil, []string{"betterleaks"}); !got.IsZero() {
			t.Fatalf("betterleaks-only sensor claimed %s; want nothing (every job left is gated)", got)
		}
		// nuclei: the nuclei job.
		if got := claim(nil, []string{"nuclei"}); got != nuclei {
			t.Fatalf("nuclei sensor claimed %s; want the nuclei job %s", got, nuclei)
		}
		// trivy matches a workflow step's preferred_tool.
		if got := claim(nil, []string{"trivy"}); got != step {
			t.Fatalf("trivy sensor claimed %s; want the trivy step %s", got, step)
		}
		// The capability gate.
		if got := claim([]string{"infra"}, nil); got != needsInfra {
			t.Fatalf("infra sensor claimed %s; want the infra job %s", got, needsInfra)
		}

		var status string
		var attempts int
		var platformSensor sql.NullString
		if err := tx.QueryRowContext(ctx,
			`SELECT status, dispatch_attempts, platform_sensor_id FROM commands WHERE id = $1`,
			nuclei.String()).Scan(&status, &attempts, &platformSensor); err != nil {
			return err
		}
		if status != "acknowledged" || attempts != 1 || platformSensor.String != sensorID.String() {
			t.Errorf("claimed job state = %s attempts=%d platform_sensor_id=%q; want acknowledged, 1, %s",
				status, attempts, platformSensor.String, sensorID)
		}
		return nil
	})
}
