package routes

// Late reports (docs/architecture/sensor-results-v2.md, "Late reports"): an
// unbound report that names the command and lease epoch it was made for
// (X-OpenCTEM-Late-Command, X-OpenCTEM-Late-Lease-Epoch) is refused with
// lease-superseded when the command was handed out again since, and goes on
// unsolicited otherwise. The headers never reach another tenant's command.
// Requires DATABASE_URL.

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/server/pkg/sensorproto/v2"
)

// putLate PUTs body as an unbound report with late provenance; epoch < 0
// sends no epoch header, commandID "" no header at all.
func (h *ctlHarness) putLate(key, reportID, commandID string, epoch int, body []byte) (*http.Response, []byte) {
	h.t.Helper()
	hdr := []string{"Content-Type", protov2.MediaTypeCTIS, protov2.HeaderContentDigest, digestOf(body)}
	if commandID != "" {
		hdr = append(hdr, protov2.HeaderLateCommand, commandID)
		if epoch >= 0 {
			hdr = append(hdr, protov2.HeaderLateLeaseEpoch, strconv.Itoa(epoch))
		}
	}
	return h.call(key, http.MethodPut, "/api/v2/sensor/results/"+reportID, body, hdr...)
}

func TestLateReports_SupersededLeaseIsRefused(t *testing.T) {
	h := newCtlHarness(t)
	a, b := h.newSensor(h.tenantID, "late-a"), h.newSensor(h.tenantID, "late-b")
	superseded := ingestProblem(string(protov2.ProblemLeaseSuperseded))

	// Re-claimed by the same sensor under a later epoch.
	again := h.newCommand(h.tenantID, a.id)
	h.holdCommand(again, a.id, 3)
	rid := newReportID()
	resp, raw := h.putLate(a.key, rid, again, 2, v2Segment("semgrep", "2.0", "late-older-epoch"))
	h.want(resp, raw, http.StatusConflict, superseded)
	if _, n := h.reportTenant(a.id, rid); n != 0 {
		t.Fatal("a late report of a superseded lease was stored")
	}

	// Handed to another sensor under the same epoch number it had.
	moved := h.newCommand(h.tenantID, "")
	h.holdCommand(moved, b.id, 1)
	rid = newReportID()
	resp, raw = h.putLate(a.key, rid, moved, 1, v2Segment("semgrep", "2.0", "late-other-holder"))
	h.want(resp, raw, http.StatusConflict, superseded)
	if _, n := h.reportTenant(a.id, rid); n != 0 {
		t.Fatal("a late report of a lease another sensor holds was stored")
	}

	// The commit of the unbound form is refused the same way.
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/results/"+newReportID()+"/commit",
		[]byte(`{"segment_count":1}`), protov2.HeaderLateCommand, again, protov2.HeaderLateLeaseEpoch, "1")
	h.want(resp, raw, http.StatusConflict, superseded)
}

func TestLateReports_CurrentLeaseIsAcceptedUnsolicited(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "late-current")
	cmd := h.newCommand(h.tenantID, s.id)
	h.holdCommand(cmd, s.id, 2)
	rid := newReportID()
	resp, raw := h.putLate(s.key, rid, cmd, 2, v2Segment("semgrep", "2.0", "late-current"))
	h.want(resp, raw, http.StatusAccepted, "")
	if tenant, n := h.reportTenant(s.id, rid); n != 1 || tenant != h.tenantID {
		t.Fatalf("late report of the current lease: %d stored in %q", n, tenant)
	}
}

// Another tenant's command, an unknown id, an epoch never handed out and no
// header at all get one answer: the report goes on unsolicited in the
// sensor's own tenant. The header cannot probe another tenant's commands.
func TestLateReports_UnknownCommandIsLikeNoHeader(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "late-unknown")
	otherTenant := h.newTenant()
	foreigner := h.newSensor(otherTenant, "late-foreign")
	foreign := h.newCommand(otherTenant, foreigner.id)
	h.holdCommand(foreign, foreigner.id, 5) // would be "superseded" for epoch 1 if it were visible
	mine := h.newCommand(h.tenantID, s.id)
	h.holdCommand(mine, s.id, 1)

	for name, tc := range map[string]struct {
		cmd   string
		epoch int
	}{
		"other tenant's command": {foreign, 1},
		"unknown command":        {shared.NewID().String(), 1},
		"epoch never handed out": {mine, 7},
		"no epoch":               {mine, -1},
		"no header":              {"", -1},
	} {
		rid := newReportID()
		resp, raw := h.putLate(s.key, rid, tc.cmd, tc.epoch, v2Segment("semgrep", "2.0", "late-"+name))
		h.want(resp, raw, http.StatusAccepted, "")
		if tenant, n := h.reportTenant(s.id, rid); n != 1 || tenant != h.tenantID {
			t.Fatalf("%s: %d stored in %q, want 1 in the sensor's tenant", name, n, tenant)
		}
	}
	// The foreign command is untouched.
	var status string
	if err := h.db.QueryRowContext(context.Background(), `SELECT status FROM commands WHERE id = $1`, foreign).Scan(&status); err != nil || status != "running" {
		t.Fatalf("foreign command %q %v", status, err)
	}
}
