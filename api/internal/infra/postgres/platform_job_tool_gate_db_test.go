package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-030 B10: get_next_platform_job used to ignore p_tools and
// p_capabilities, so a platform sensor could claim a job for a tool it does
// not have. Requires DATABASE_URL (CI applies every migration first).
func TestGetNextPlatformJob_ToolAndCapabilityGates(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	sensorID := seedJobSensor(ctx, t, db, tenantID)

	// Queue priorities far above anything else in the queue, so the jobs
	// under test are the ones the function looks at first.
	seed := func(payload string, priority int) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO commands (id, tenant_id, type, priority, payload, status, is_platform_job, queue_priority, queued_at)
			VALUES ($1, $2, 'scan', 'normal', $3::jsonb, 'pending', TRUE, $4, NOW())`,
			id.String(), tenantID.String(), payload, priority); err != nil {
			t.Fatalf("seed platform job: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE id = $1`, id.String())
		})
		return id
	}
	nuclei := seed(`{"scanner":"nuclei"}`, 900000003)
	step := seed(`{"preferred_tool":"trivy"}`, 900000002)
	needsInfra := seed(`{"required_capabilities":["infra"]}`, 900000001)
	plain := seed(`{"kind":"collect"}`, 900000000)

	claim := func(caps, tools []string) shared.ID {
		t.Helper()
		cmd, err := repo.GetNextPlatformJob(ctx, sensorID, caps, tools)
		if err != nil {
			t.Fatalf("GetNextPlatformJob: %v", err)
		}
		if cmd == nil {
			return shared.ID{}
		}
		return cmd.ID
	}

	// A sensor with no tools and no capabilities skips the nuclei job, the
	// trivy step and the infra job, and gets the plain one.
	if got := claim(nil, nil); got != plain {
		t.Fatalf("sensor without tools claimed %s; want the tool-less job %s", got, plain)
	}
	// betterleaks only: still none of the gated jobs.
	if got := claim(nil, []string{"betterleaks"}); got == nuclei || got == step || got == needsInfra {
		t.Fatalf("betterleaks-only sensor claimed a gated job %s", got)
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
	status, attempts, _, platformSet := commandState(ctx, t, db, nuclei)
	if status != "acknowledged" || attempts != 1 || !platformSet {
		t.Errorf("claimed job state = %s attempts=%d platform_sensor_set=%v; want acknowledged, 1, true", status, attempts, platformSet)
	}
}
