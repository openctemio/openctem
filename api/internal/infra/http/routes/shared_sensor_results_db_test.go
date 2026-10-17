package routes

// Result binding for shared sensors (scope instance,
// docs/rfcs/RFC-100-shared-sensors.md §8, RFC-040 §11.2): a shared sensor
// has no tenant. It may write only the results of a shared job it holds
// under the lease epoch it states, and they go into the COMMAND's tenant,
// whatever the request says. It never pushes unsolicited results. An
// organization sensor never posts results for, nor receives, a shared job.
// Requires DATABASE_URL.

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// newSharedSensor creates a shared sensor (scope instance, no tenant) that
// verified semgrep.
func (h *ctlHarness) newSharedSensor(name string) ctlSensor {
	h.t.Helper()
	key, err := sensorkey.New(sensorkey.PrefixSensorKey)
	if err != nil {
		h.t.Fatal(err)
	}
	s, err := sensordom.NewSensor(shared.NewID(), name, sensordom.SensorTypeWorker, "", nil, sensordom.ExecutionModeDaemon)
	if err != nil {
		h.t.Fatal(err)
	}
	s.Scope, s.TenantID = sensordom.ScopeInstance, nil
	s.SetAPIKey(crypto.HashTokenPeppered(key, ""), sensorkey.DisplayPrefix(key))
	if err := h.repo.Create(context.Background(), s); err != nil {
		h.t.Fatalf("create shared sensor: %v", err)
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM ingest_reports WHERE sensor_id = $1`, s.ID.String())
		_, _ = h.db.ExecContext(ctx, `DELETE FROM commands WHERE sensor_id = $1`, s.ID.String())
		_, _ = h.db.ExecContext(ctx, `DELETE FROM sensors WHERE id = $1`, s.ID.String())
	})
	out := ctlSensor{id: s.ID.String(), key: key, tools: []string{"semgrep"}}
	h.verifyTools(out)
	return out
}

// sharedJob creates a shared job (is_platform_job) in tenantID. With a
// holder it is running for that sensor under lease epoch epoch; without one
// it is pending and unpinned.
func (h *ctlHarness) sharedJob(tenantID, holder string, epoch int) string {
	h.t.Helper()
	id := h.newCommand(tenantID, "")
	var err error
	if holder == "" {
		_, err = h.db.ExecContext(context.Background(), `UPDATE commands SET is_platform_job = TRUE WHERE id = $1`, id)
	} else {
		_, err = h.db.ExecContext(context.Background(), `
			UPDATE commands SET is_platform_job = TRUE, status = 'running', sensor_id = $2, lease_epoch = $3,
			       acknowledged_at = now(), started_at = now(), lease_expires_at = now() + interval '10 minutes'
			WHERE id = $1`, id, holder, epoch)
	}
	if err != nil {
		h.t.Fatalf("shared job: %v", err)
	}
	return id
}

// putBound sends a whole command-bound report; epoch < 0 sends no lease
// epoch header. extra headers follow.
func (h *ctlHarness) putBound(key, commandID, reportID string, epoch int, body []byte, extra ...string) (*http.Response, []byte) {
	h.t.Helper()
	hdr := []string{"Content-Type", protov2.MediaTypeCTIS, protov2.HeaderContentDigest, digestOf(body)}
	if epoch >= 0 {
		hdr = append(hdr, protov2.HeaderLeaseEpoch, strconv.Itoa(epoch))
	}
	hdr = append(hdr, extra...)
	path := "/api/v2/sensor/commands/" + strings.ToLower(commandID) + "/results/" + reportID
	return h.call(key, http.MethodPut, path, body, hdr...)
}

func (h *ctlHarness) reportTenant(sensorID, reportID string) (tenant string, n int) {
	h.t.Helper()
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT COALESCE(max(tenant_id::text), ''), count(*) FROM ingest_reports WHERE sensor_id = $1 AND report_id = $2`,
		sensorID, reportID).Scan(&tenant, &n); err != nil {
		h.t.Fatal(err)
	}
	return tenant, n
}

// processReports runs the ingest worker over every job of the reports
// sensorID sent (the harness queues them without a worker).
func (h *ctlHarness) processReports(sensorID string) {
	h.t.Helper()
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		h.repo, postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), log)
	svc.SetCommandReader(postgres.NewCommandRepository(db))
	reports, jobs := postgres.NewIngestReportRepository(db), postgres.NewIngestJobRepository(db)
	proc := ingest.NewV2JobProcessor(svc, reports, jobs, protov2.DefaultLimits(), ingest.DefaultBlindingGuard(), log)
	var refs []string
	func() {
		rows, err := h.db.QueryContext(ctx, `SELECT id FROM ingest_reports WHERE sensor_id = $1`, sensorID)
		if err != nil {
			h.t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				h.t.Fatal(err)
			}
			refs = append(refs, id)
		}
		if err := rows.Err(); err != nil {
			h.t.Fatal(err)
		}
	}()
	for _, ref := range refs {
		rid := shared.MustIDFromString(ref)
		digests, _ := jobs.V2SegmentDigests(ctx, rid)
		for seq := range digests {
			job, err := jobs.GetV2Segment(ctx, rid, seq)
			if err != nil {
				h.t.Fatal(err)
			}
			if _, err := proc.Process(ctx, job); err != nil {
				h.t.Fatalf("process: %v", err)
			}
		}
		if job, err := jobs.GetV2Commit(ctx, rid); err == nil {
			if _, err := proc.Process(ctx, job); err != nil {
				h.t.Fatalf("process commit: %v", err)
			}
		}
	}
}

func (h *ctlHarness) findingsOf(tenantID, ruleID string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM findings WHERE tenant_id = $1 AND rule_id = $2`, tenantID, ruleID).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func (h *ctlHarness) findingsAnywhere(ruleID string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM findings WHERE rule_id = $1`, ruleID).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// TestSharedResults_BoundToCommandTenant: a shared sensor's results for a
// shared job it holds are written into the command's tenant, and nothing the
// request names (a tenant query parameter or header) changes that.
func TestSharedResults_BoundToCommandTenant(t *testing.T) {
	h := newCtlHarness(t)
	tenantX, tenantY := h.tenantID, h.newTenant()
	a := h.newSharedSensor("shared-a")
	jobX := h.sharedJob(tenantX, a.id, 3)

	rule := "shared-bind-" + shared.NewID().String()
	rid := newReportID()
	resp, raw := h.putBound(a.key, jobX, rid+"?tenant_id="+tenantY+"&organization_id="+tenantY, 3, v2Segment("semgrep", "1.0", rule),
		"X-Tenant-ID", tenantY, "X-OpenCTEM-Tenant", tenantY)
	h.want(resp, raw, 202, "")
	if tenant, n := h.reportTenant(a.id, rid); n != 1 || tenant != tenantX {
		t.Fatalf("report stored in tenant %q (%d rows), want the command's tenant %s", tenant, n, tenantX)
	}

	h.processReports(a.id)
	if got := h.findingsOf(tenantX, rule); got == 0 {
		t.Fatalf("no finding in the command's tenant")
	}
	if got := h.findingsOf(tenantY, rule); got != 0 {
		t.Fatalf("%d findings written into another tenant", got)
	}
	if all, inX := h.findingsAnywhere(rule), h.findingsOf(tenantX, rule); all != inX {
		t.Fatalf("findings outside the command's tenant: %d of %d", all-inX, all)
	}
}

// TestSharedResults_RefusedForJobNotHeld: a shared sensor cannot post
// results for a job held by another shared sensor (another tenant's or the
// same tenant's), for a tenant job, under an old or missing lease epoch, or
// without a command at all (push).
func TestSharedResults_RefusedForJobNotHeld(t *testing.T) {
	h := newCtlHarness(t)
	tenantX, tenantY := h.tenantID, h.newTenant()
	a, b := h.newSharedSensor("shared-a"), h.newSharedSensor("shared-b")
	org := h.newSensor(tenantX, "org-x")

	jobX := h.sharedJob(tenantX, a.id, 3)  // held by A
	jobY := h.sharedJob(tenantY, b.id, 1)  // tenant Y, held by B
	jobXB := h.sharedJob(tenantX, b.id, 1) // tenant X, held by B
	tenantJob := h.newCommand(tenantX, org.id)
	if _, err := h.db.ExecContext(context.Background(), `
		UPDATE commands SET status = 'running', sensor_id = $2, lease_epoch = 1, acknowledged_at = now(), started_at = now()
		WHERE id = $1`, tenantJob, org.id); err != nil {
		t.Fatal(err)
	}

	body := v2Segment("semgrep", "1.0", "refused")
	notFound := ingestProblem(string(protov2.ProblemCommandNotFound))
	for name, c := range map[string]struct {
		cmd   string
		epoch int
	}{
		"another tenant's job held by B": {jobY, 1},
		"same tenant's job held by B":    {jobXB, 1},
		"a tenant job":                   {tenantJob, 1},
		"its own job, old epoch":         {jobX, 2},
		"its own job, no epoch":          {jobX, -1},
		"an unknown command":             {shared.NewID().String(), 1},
	} {
		t.Run(name, func(t *testing.T) {
			rid := newReportID()
			resp, raw := h.putBound(a.key, c.cmd, rid, c.epoch, body)
			h.want(resp, raw, http.StatusNotFound, notFound)
			if _, n := h.reportTenant(a.id, rid); n != 0 {
				t.Fatalf("a refused report was stored")
			}
		})
	}

	// Push (no command): refused, a shared sensor never sends unsolicited results.
	resp, raw := h.call(a.key, http.MethodPut, "/api/v2/sensor/results/"+newReportID(), body,
		"Content-Type", protov2.MediaTypeCTIS, protov2.HeaderContentDigest, digestOf(body))
	h.want(resp, raw, http.StatusForbidden, ingestProblem(string(protov2.ProblemScopeDenied)))

	// The current epoch is accepted (the control case).
	resp, raw = h.putBound(a.key, jobX, newReportID(), 3, body)
	h.want(resp, raw, 202, "")
}

// TestSharedResults_DroppedWhenNoLongerHeld: a report accepted while the
// sensor held the job is not applied when the job was taken from it (lease
// expired and another sensor claimed it) before the worker ran.
func TestSharedResults_DroppedWhenNoLongerHeld(t *testing.T) {
	h := newCtlHarness(t)
	a, b := h.newSharedSensor("shared-a"), h.newSharedSensor("shared-b")
	job := h.sharedJob(h.tenantID, a.id, 3)
	rule := "shared-drop-" + shared.NewID().String()
	rid := newReportID()
	resp, raw := h.putBound(a.key, job, rid, 3, v2Segment("semgrep", "1.0", rule))
	h.want(resp, raw, 202, "")
	if _, err := h.db.ExecContext(context.Background(),
		`UPDATE commands SET sensor_id = $2, lease_epoch = 4 WHERE id = $1`, job, b.id); err != nil {
		t.Fatal(err)
	}
	h.processReports(a.id)
	if n := h.findingsAnywhere(rule); n != 0 {
		t.Fatalf("%d findings applied from a sensor that no longer holds the job", n)
	}
	var state string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT state FROM ingest_reports WHERE sensor_id = $1 AND report_id = $2`, a.id, rid).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != string(protov2.StateFailed) {
		t.Fatalf("report state %q, want failed", state)
	}
}

// TestOrganizationSensor_CannotPostSharedJobResults: an organization sensor
// posts results only for its own tenant's jobs it holds; a shared job is
// never one of them, even one of its own tenant, and even if its row named
// that sensor as the holder.
func TestOrganizationSensor_CannotPostSharedJobResults(t *testing.T) {
	h := newCtlHarness(t)
	a := h.newSharedSensor("shared-a")
	org := h.newSensor(h.tenantID, "org-x")
	heldByShared := h.sharedJob(h.tenantID, a.id, 1)
	namesOrg := h.sharedJob(h.tenantID, org.id, 1)

	body := v2Segment("semgrep", "1.0", "org-shared")
	notFound := ingestProblem(string(protov2.ProblemCommandNotFound))
	for _, id := range []string{heldByShared, namesOrg} {
		rid := newReportID()
		resp, raw := h.putBound(org.key, id, rid, 1, body)
		h.want(resp, raw, http.StatusNotFound, notFound)
		if _, n := h.reportTenant(org.id, rid); n != 0 {
			t.Fatalf("a refused report was stored")
		}
	}
}

// TestOrganizationSensor_NeverReceivesSharedJob: at the v2 handler, an
// organization sensor's poll, claim-N and claim by id never hand it a shared
// job of its own tenant (whose signed statement would say sensor_scope
// instance); its tenant job is handed out.
func TestOrganizationSensor_NeverReceivesSharedJob(t *testing.T) {
	h := newCtlHarness(t)
	org := h.newSensor(h.tenantID, "org-x")
	sharedID := h.sharedJob(h.tenantID, "", 0)
	tenantJob := h.newCommand(h.tenantID, "")

	if ids := h.pollIDs(org, "/api/v2/sensor/commands?limit=10"); strings.Contains(strings.Join(ids, ","), sharedID) ||
		!strings.Contains(strings.Join(ids, ","), tenantJob) {
		t.Fatalf("poll returned %v; want the tenant job %s and never the shared job %s", ids, tenantJob, sharedID)
	}
	resp, raw := h.call(org.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	got := decodeAs[wireCommandList](t, raw)
	for _, c := range got.Commands {
		if c.ID == sharedID {
			t.Fatalf("claim-N handed the organization sensor a shared job: %s", raw)
		}
	}
	resp, raw = h.call(org.key, http.MethodPost, "/api/v2/sensor/commands/"+sharedID+"/claim", nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("claim by id of a shared job succeeded: %s", raw)
	}
	status, holder, _ := h.commandState(sharedID)
	if status != "pending" || holder != nil {
		t.Fatalf("shared job is %s held by %v; want pending and unheld", status, holder)
	}
}

// TestSharedResults_DatabaseRefusesUnboundReport: the database itself keeps
// the binding: a shared sensor's report row must name a shared job of the
// row's tenant that the sensor holds, and an organization sensor's report row
// stays in the sensor's tenant.
func TestSharedResults_DatabaseRefusesUnboundReport(t *testing.T) {
	h := newCtlHarness(t)
	tenantX, tenantY := h.tenantID, h.newTenant()
	a := h.newSharedSensor("shared-a")
	org := h.newSensor(tenantX, "org-x")
	jobX := h.sharedJob(tenantX, a.id, 1)

	insert := func(tenant, sensorID string, command any) error {
		_, err := h.db.ExecContext(context.Background(), `
			INSERT INTO ingest_reports (id, tenant_id, sensor_id, report_id, command_id, state, media_type, header_digest, expires_at)
			VALUES ($1, $2, $3, $4, $5, 'receiving', 'application/vnd.ctis+json', 'sha-256=:x:', now() + interval '1 hour')`,
			shared.NewID().String(), tenant, sensorID, newReportID(), command)
		return err
	}
	for name, c := range map[string]struct {
		tenant, sensor string
		command        any
	}{
		"shared sensor, no command":            {tenantX, a.id, nil},
		"shared sensor, job of another tenant": {tenantY, a.id, jobX},
		"organization sensor, other tenant":    {tenantY, org.id, nil},
	} {
		if err := insert(c.tenant, c.sensor, c.command); err == nil {
			t.Errorf("%s: report row stored", name)
		}
	}
	if err := insert(tenantX, a.id, jobX); err != nil {
		t.Fatalf("the bound report of a held shared job was refused: %v", err)
	}
	if err := insert(tenantX, org.id, nil); err != nil {
		t.Fatalf("an organization sensor's own report was refused: %v", err)
	}
}
