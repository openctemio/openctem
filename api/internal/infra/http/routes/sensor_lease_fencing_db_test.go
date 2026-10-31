package routes

// Lease fencing of an organization sensor's results and claim hand-back
// (docs/architecture/sensor-platform-workflow.md, edge cases "Network loss
// longer than the lease" and "Delivery fails after a claim"). Requires
// DATABASE_URL.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// holdCommand sets a command running for sensorID under lease epoch epoch.
func (h *ctlHarness) holdCommand(id, sensorID string, epoch int) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), `
		UPDATE commands SET status = 'running', sensor_id = $2, lease_epoch = $3, acknowledged_at = now(),
		       started_at = now(), lease_expires_at = now() + interval '10 minutes'
		WHERE id = $1`, id, sensorID, epoch); err != nil {
		h.t.Fatalf("hold command: %v", err)
	}
}

func (h *ctlHarness) reportState(sensorID, reportID string) string {
	h.t.Helper()
	var state string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT state FROM ingest_reports WHERE sensor_id = $1 AND report_id = $2`, sensorID, reportID).Scan(&state); err != nil {
		h.t.Fatal(err)
	}
	return state
}

// An organization sensor that states an old lease epoch is refused like an
// unknown command; the current epoch, or none, is accepted.
func TestOrgResults_StatedEpochMustBeCurrent(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "org")
	cmd := h.newCommand(h.tenantID, s.id)
	h.holdCommand(cmd, s.id, 2)

	notFound := ingestProblem(string(protov2.ProblemCommandNotFound))
	rid := newReportID()
	resp, raw := h.putBound(s.key, cmd, rid, 1, v2Segment("semgrep", "1.0", "epoch-old"))
	h.want(resp, raw, http.StatusNotFound, notFound)
	if _, n := h.reportTenant(s.id, rid); n != 0 {
		t.Fatal("a report of an old epoch was stored")
	}
	resp, raw = h.putBound(s.key, cmd, newReportID(), 2, v2Segment("semgrep", "1.0", "epoch-current"))
	h.want(resp, raw, 202, "")
	resp, raw = h.putBound(s.key, cmd, newReportID(), -1, v2Segment("semgrep", "1.0", "epoch-none"))
	h.want(resp, raw, 202, "")

	// Another tenant's sensor stating the right epoch gets nothing either.
	other := h.newSensor(h.newTenant(), "other")
	resp, raw = h.putBound(other.key, cmd, newReportID(), 2, v2Segment("semgrep", "1.0", "epoch-cross"))
	h.want(resp, raw, http.StatusNotFound, notFound)
}

// A report accepted while the sensor held the command is not applied when
// the run was taken back before the worker reached it: re-claimed by the
// same sensor (a new epoch) or by another sensor. An undisturbed run's
// report is applied.
func TestOrgResults_QueuedReportOfATakenBackRunIsDropped(t *testing.T) {
	h := newCtlHarness(t)
	a, b := h.newSensor(h.tenantID, "org-a"), h.newSensor(h.tenantID, "org-b")

	cases := []struct {
		name  string
		after func(cmd string)
		kept  bool
	}{
		{"undisturbed", func(string) {}, true},
		{"re-claimed by the same sensor", func(cmd string) { h.holdCommand(cmd, a.id, 4) }, false},
		{"re-claimed by another sensor", func(cmd string) { h.holdCommand(cmd, b.id, 4) }, false},
		{"re-queued and waiting", func(cmd string) {
			if _, err := h.db.ExecContext(context.Background(),
				`UPDATE commands SET status = 'pending', sensor_id = NULL, lease_expires_at = NULL WHERE id = $1`, cmd); err != nil {
				t.Fatal(err)
			}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := h.newCommand(h.tenantID, a.id)
			h.holdCommand(cmd, a.id, 3)
			rule := "fence-" + shared.NewID().String()
			rid := newReportID()
			resp, raw := h.putBound(a.key, cmd, rid, -1, v2Segment("semgrep", "1.0", rule))
			h.want(resp, raw, 202, "")
			c.after(cmd)
			h.processReports(a.id)
			n := h.findingsAnywhere(rule)
			switch {
			case c.kept && n != 1:
				t.Fatalf("an undisturbed run's report was not applied (%d findings)", n)
			case !c.kept && n != 0:
				t.Fatalf("%d findings applied from a run that was taken back", n)
			case !c.kept && h.reportState(a.id, rid) != string(protov2.StateFailed):
				t.Fatalf("report state %q, want failed", h.reportState(a.id, rid))
			}
		})
	}
}

// failingPolicy is a tenant HTTP policy that cannot be read.
type failingPolicy struct{ fail *bool }

func (p failingPolicy) ToolHTTPPolicy(context.Context, shared.ID) (sensordom.ToolHTTPPolicy, error) {
	if *p.fail {
		return sensordom.ToolHTTPPolicy{}, errors.New("settings store unavailable")
	}
	return sensordom.ToolHTTPPolicy{}, nil
}

// A claim-N whose delivery fails (the tenant policy cannot be read) hands
// every claimed command back at once: pending, the pin kept as it was, no
// lease, so no attempt is booked and the healthy sensor is never excluded.
// Once the policy reads again the same commands go out.
func TestClaimN_DeliveryFailureHandsTheClaimBack(t *testing.T) {
	fail := true
	h := newCtlHarness(t, command.WithHTTPPolicy(failingPolicy{fail: &fail}))
	s := h.newSensor(h.tenantID, "claimer")
	h.setMaxJobs(s.id, 5)
	unpinned := h.newCommand(h.tenantID, "")
	pinned := h.newCommand(h.tenantID, s.id)

	resp, raw := h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	if resp.StatusCode == http.StatusOK {
		if l := decodeAs[wireCommandList](t, raw); len(l.Commands) != 0 {
			t.Fatalf("commands handed out without the tenant's policy: %s", raw)
		}
	}
	if st, sensor, leased := h.commandState(unpinned); st != "pending" || sensor != nil || leased {
		t.Fatalf("unpinned command %s %v leased=%v; want pending, unpinned, no lease", st, sensor, leased)
	}
	if st, sensor, leased := h.commandState(pinned); st != "pending" || sensor == nil || *sensor != s.id || leased {
		t.Fatalf("pinned command %s %v leased=%v; want pending and still pinned", st, sensor, leased)
	}
	for _, id := range []string{unpinned, pinned} {
		var failedOn, attempts int
		if err := h.db.QueryRowContext(context.Background(),
			`SELECT cardinality(failed_on), jsonb_array_length(attempts) FROM commands WHERE id = $1`, id).Scan(&failedOn, &attempts); err != nil {
			t.Fatal(err)
		}
		if failedOn != 0 || attempts != 0 {
			t.Fatalf("command %s: failed_on %d, attempts %d; a platform failure was booked against the sensor", id, failedOn, attempts)
		}
	}

	fail = false
	if _, err := h.db.ExecContext(context.Background(), `UPDATE commands SET scheduled_at = NULL WHERE id IN ($1, $2)`, unpinned, pinned); err != nil {
		t.Fatal(err)
	}
	resp, raw = h.call(s.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	if l := decodeAs[wireCommandList](t, raw); len(l.Commands) != 2 {
		t.Fatalf("after recovery: %s", raw)
	}
}

// A shared sensor's queued report is dropped when its job was handed to it
// again under a new epoch, as an organization sensor's is.
func TestSharedResults_QueuedReportOfAnOlderEpochIsDropped(t *testing.T) {
	h := newCtlHarness(t)
	a := h.newSharedSensor("shared-epoch")
	job := h.sharedJob(h.tenantID, a.id, 3)
	rule := "shared-epoch-" + shared.NewID().String()
	rid := newReportID()
	resp, raw := h.putBound(a.key, job, rid, 3, v2Segment("semgrep", "1.0", rule))
	h.want(resp, raw, 202, "")
	if _, err := h.db.ExecContext(context.Background(), `UPDATE commands SET lease_epoch = 4 WHERE id = $1`, job); err != nil {
		t.Fatal(err)
	}
	h.processReports(a.id)
	if n := h.findingsAnywhere(rule); n != 0 {
		t.Fatalf("%d findings applied from an older run of the shared job", n)
	}
	if st := h.reportState(a.id, rid); st != string(protov2.StateFailed) {
		t.Fatalf("report state %q, want failed", st)
	}
}
