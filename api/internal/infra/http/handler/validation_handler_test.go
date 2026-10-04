package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// --- fakes (package handler can only use validation's exported surface) ---

type fakeEvidenceRepo struct {
	rows []validation.StoredEvidence
}

func (f *fakeEvidenceRepo) Create(_ context.Context, ev validation.StoredEvidence) error {
	f.rows = append(f.rows, ev)
	return nil
}

func (f *fakeEvidenceRepo) ListByFinding(_ context.Context, tenantID, findingID shared.ID) ([]validation.StoredEvidence, error) {
	var out []validation.StoredEvidence
	for _, r := range f.rows {
		if r.TenantID == tenantID && r.FindingID == findingID {
			out = append(out, r)
		}
	}
	return out, nil
}

type fakeFindingMutator struct {
	current *vulnerability.Finding
	getErr  error
}

func (f *fakeFindingMutator) Get(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.current, nil
}

func (f *fakeFindingMutator) Update(_ context.Context, fnd *vulnerability.Finding) error {
	f.current = fnd
	return nil
}

func fixAppliedFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceManual, "T-1",
		vulnerability.SeverityHigh, "test",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	for _, st := range []vulnerability.FindingStatus{
		vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress,
		vulnerability.FindingStatusFixApplied,
	} {
		if err := f.TransitionStatus(st, "", nil); err != nil {
			t.Fatalf("transition %s: %v", st, err)
		}
	}
	return f
}

// advisoryPolicy is a tenant result policy with advisory evidence on or off.
type advisoryPolicy bool

func (a advisoryPolicy) ResultPolicy(_ context.Context, tenantID shared.ID) sensorresult.Policy {
	return sensorresult.Policy{TenantID: tenantID, Mode: sensorresult.ModeQuarantine, AllowAdvisoryEvidence: bool(a)}
}

// newValidationHandler builds the handler for a tenant that allows advisory
// evidence, so the tests below reach the evidence path without a command.
func newValidationHandler(repo *fakeEvidenceRepo, fm *fakeFindingMutator) *ValidationHandler {
	store := validation.NewEvidenceStore(repo)
	svc := validation.NewEvidenceIngestService(store, fm, nil, nil, logger.NewNop())
	h := NewValidationHandler(svc, logger.NewNop())
	h.SetEvidencePolicy(advisoryPolicy(true))
	return h
}

func sensorCtxReq(t *testing.T, method, target string, body []byte, tenantID shared.ID) *http.Request {
	t.Helper()
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	tid := tenantID
	agt := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Status: sensor.SensorStatusActive}
	return r.WithContext(context.WithValue(r.Context(), sensorContextKey, agt))
}

// With the validate command assigned to the submitting sensor for this finding
// cited, the evidence is authoritative and moves the finding.
func TestValidationHandler_IngestEvidence_Resolves(t *testing.T) {
	repo := &fakeEvidenceRepo{}
	fm := &fakeFindingMutator{current: fixAppliedFinding(t)}
	h := newValidationHandler(repo, fm)

	tenantID := shared.NewID()
	findingID := shared.NewID()
	r0 := sensorCtxReq(t, http.MethodPost, "/api/v1/validation/evidence", nil, tenantID)
	sensorID := SensorFromContext(r0.Context()).ID
	cmd := validateCmd(t, tenantID, &sensorID, findingID, commanddom.CommandStatusRunning)
	h.SetCommandLookup(&fakeCommandLookup{cmds: []*commanddom.Command{cmd}})

	body, _ := json.Marshal(evidenceRequest{
		FindingID:    findingID.String(),
		CommandID:    cmd.ID.String(),
		ExecutorKind: "nuclei",
		Technique:    "T1190",
		Outcome:      "not_detected",
		Summary:      "exposure gone",
		RawMeta:      map[string]any{"reachable": true},
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/validation/evidence", bytes.NewReader(body)).WithContext(r0.Context())
	w := httptest.NewRecorder()

	h.IngestEvidence(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	var resp evidenceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode resp: %v", err)
	}
	if !resp.StatusChanged {
		t.Error("expected status_changed=true")
	}
	if len(repo.rows) != 1 {
		t.Fatalf("evidence rows = %d, want 1", len(repo.rows))
	}
	if repo.rows[0].TenantID != tenantID {
		t.Error("evidence tenant must come from the sensor context, not the body")
	}
	if fm.current.Status() != vulnerability.FindingStatusResolved {
		t.Errorf("finding status = %s, want resolved", fm.current.Status())
	}
}

func TestValidationHandler_IngestEvidence_NoSensor_Unauthorized(t *testing.T) {
	h := newValidationHandler(&fakeEvidenceRepo{}, &fakeFindingMutator{current: fixAppliedFinding(t)})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/validation/evidence", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()

	h.IngestEvidence(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestValidationHandler_IngestEvidence_BadOutcome(t *testing.T) {
	h := newValidationHandler(&fakeEvidenceRepo{}, &fakeFindingMutator{current: fixAppliedFinding(t)})
	body, _ := json.Marshal(evidenceRequest{
		FindingID:    shared.NewID().String(),
		ExecutorKind: "safe-check",
		Outcome:      "bogus-outcome",
	})
	r := sensorCtxReq(t, http.MethodPost, "/api/v1/validation/evidence", body, shared.NewID())
	w := httptest.NewRecorder()

	h.IngestEvidence(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestValidationHandler_IngestEvidence_MissingFindingID(t *testing.T) {
	h := newValidationHandler(&fakeEvidenceRepo{}, &fakeFindingMutator{current: fixAppliedFinding(t)})
	body, _ := json.Marshal(evidenceRequest{ExecutorKind: "safe-check", Outcome: "not_detected"})
	r := sensorCtxReq(t, http.MethodPost, "/api/v1/validation/evidence", body, shared.NewID())
	w := httptest.NewRecorder()

	h.IngestEvidence(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestValidationHandler_IngestEvidence_FindingNotFound(t *testing.T) {
	h := newValidationHandler(&fakeEvidenceRepo{}, &fakeFindingMutator{getErr: shared.ErrNotFound})
	body, _ := json.Marshal(evidenceRequest{
		FindingID:    shared.NewID().String(),
		ExecutorKind: "safe-check",
		Outcome:      "not_detected",
	})
	r := sensorCtxReq(t, http.MethodPost, "/api/v1/validation/evidence", body, shared.NewID())
	w := httptest.NewRecorder()

	h.IngestEvidence(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestValidationHandler_ListFindingEvidence(t *testing.T) {
	repo := &fakeEvidenceRepo{}
	fm := &fakeFindingMutator{current: fixAppliedFinding(t)}
	h := newValidationHandler(repo, fm)

	tenantID, findingID := shared.NewID(), shared.NewID()
	// Seed one row via the ingest path so list returns it.
	body, _ := json.Marshal(evidenceRequest{
		FindingID:    findingID.String(),
		ExecutorKind: "safe-check",
		Outcome:      "inconclusive",
	})
	ingestReq := sensorCtxReq(t, http.MethodPost, "/api/v1/validation/evidence", body, tenantID)
	h.IngestEvidence(httptest.NewRecorder(), ingestReq)

	// Now GET the list with JWT tenant context + chi url param.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingID.String()+"/evidence", nil)
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID.String())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", findingID.String())
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.ListFindingEvidence(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Evidence []storedEvidenceOut `json:"evidence"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Evidence) != 1 {
		t.Fatalf("evidence len = %d, want 1", len(resp.Evidence))
	}
	if resp.Evidence[0].Outcome != "inconclusive" {
		t.Errorf("outcome = %q, want inconclusive", resp.Evidence[0].Outcome)
	}
}

// --- command-authorization of direct evidence submissions -----------------

type fakeCommandLookup struct{ cmds []*commanddom.Command }

func (f *fakeCommandLookup) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*commanddom.Command, error) {
	for _, c := range f.cmds {
		if c.ID == id && c.TenantID == tenantID {
			return c, nil
		}
	}
	return nil, shared.ErrNotFound
}

func validateCmd(t *testing.T, tenantID shared.ID, sensorID *shared.ID, findingID shared.ID, status commanddom.CommandStatus) *commanddom.Command {
	t.Helper()
	payload, _ := json.Marshal(validation.ValidateCommandPayload{FindingID: findingID.String(), ExecutorKind: "safe-check"})
	cmd, err := commanddom.NewCommand(tenantID, commanddom.CommandTypeValidate, commanddom.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatalf("new command: %v", err)
	}
	if sensorID != nil {
		cmd.SetSensorID(*sensorID)
	}
	cmd.Status = status
	return cmd
}

// postEvidence submits an outcome for findingID as the given sensor.
func postEvidence(t *testing.T, h *ValidationHandler, tenantID, sensorID, findingID shared.ID, commandID string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(evidenceRequest{
		FindingID: findingID.String(), CommandID: commandID,
		ExecutorKind: "safe-check", Outcome: "not_detected",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/validation/evidence", bytes.NewReader(body))
	tid := tenantID
	agt := &sensor.Sensor{ID: sensorID, TenantID: &tid, Status: sensor.SensorStatusActive}
	r = r.WithContext(context.WithValue(r.Context(), sensorContextKey, agt))
	w := httptest.NewRecorder()
	h.IngestEvidence(w, r)
	return w
}

// ATTACK: any sensor key in the tenant posting an outcome for an arbitrary
// finding id (no command) must not change the finding — evidence is stored as
// advisory only and the response shape is unchanged.
func TestValidationHandler_IngestEvidence_NoCommand_AdvisoryOnly(t *testing.T) {
	repo := &fakeEvidenceRepo{}
	fm := &fakeFindingMutator{current: fixAppliedFinding(t)}
	h := newValidationHandler(repo, fm)
	h.SetCommandLookup(&fakeCommandLookup{})

	w := postEvidence(t, h, shared.NewID(), shared.NewID(), shared.NewID(), "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	var resp evidenceResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.StatusChanged || resp.Downgraded {
		t.Error("advisory evidence must not report a status change")
	}
	if fm.current.Status() != vulnerability.FindingStatusFixApplied {
		t.Fatalf("unsolicited evidence moved the finding to %s", fm.current.Status())
	}
	if len(repo.rows) != 1 {
		t.Fatalf("advisory evidence must still be stored, rows=%d", len(repo.rows))
	}
}

// RFC-040 §5.3: evidence without a command is refused unless the tenant's
// policy allows advisory evidence, which it does not by default (and not when
// no policy reader is wired). Nothing is stored and the finding is untouched.
func TestValidationHandler_IngestEvidence_NoCommand_RefusedByDefault(t *testing.T) {
	for name, policy := range map[string]EvidencePolicyReader{"policy off": advisoryPolicy(false), "no policy reader": nil} {
		t.Run(name, func(t *testing.T) {
			repo := &fakeEvidenceRepo{}
			fm := &fakeFindingMutator{current: fixAppliedFinding(t)}
			h := newValidationHandler(repo, fm)
			h.SetEvidencePolicy(policy)
			h.SetCommandLookup(&fakeCommandLookup{})

			w := postEvidence(t, h, shared.NewID(), shared.NewID(), shared.NewID(), "")
			if w.Code != http.StatusForbidden || !bytes.Contains(w.Body.Bytes(), []byte("COMMAND_REQUIRED")) {
				t.Fatalf("status = %d, want 403 COMMAND_REQUIRED; body=%s", w.Code, w.Body.String())
			}
			if len(repo.rows) != 0 {
				t.Fatalf("refused evidence was stored, rows=%d", len(repo.rows))
			}
			if fm.current.Status() != vulnerability.FindingStatusFixApplied {
				t.Fatalf("refused evidence moved the finding to %s", fm.current.Status())
			}
		})
	}
}

// ATTACK: citing a command that is not this sensor's / not a validate command /
// already finished / for another finding is rejected with 403 and changes
// nothing.
func TestValidationHandler_IngestEvidence_ForeignOrStaleCommandRejected(t *testing.T) {
	tenantID := shared.NewID()
	me := shared.NewID()
	other := shared.NewID()
	findingID := shared.NewID()

	scanCmd, _ := commanddom.NewCommand(tenantID, commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, json.RawMessage(`{"finding_id":"`+findingID.String()+`"}`))
	scanCmd.SetSensorID(me)
	scanCmd.Status = commanddom.CommandStatusRunning

	cases := map[string]*commanddom.Command{
		"other sensor":       validateCmd(t, tenantID, &other, findingID, commanddom.CommandStatusRunning),
		"unassigned":         validateCmd(t, tenantID, nil, findingID, commanddom.CommandStatusPending),
		"completed":          validateCmd(t, tenantID, &me, findingID, commanddom.CommandStatusCompleted),
		"failed":             validateCmd(t, tenantID, &me, findingID, commanddom.CommandStatusFailed),
		"other finding":      validateCmd(t, tenantID, &me, shared.NewID(), commanddom.CommandStatusRunning),
		"not validate":       scanCmd,
		"other tenant (404)": validateCmd(t, shared.NewID(), &me, findingID, commanddom.CommandStatusRunning),
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &fakeEvidenceRepo{}
			fm := &fakeFindingMutator{current: fixAppliedFinding(t)}
			h := newValidationHandler(repo, fm)
			h.SetCommandLookup(&fakeCommandLookup{cmds: []*commanddom.Command{cmd}})

			w := postEvidence(t, h, tenantID, me, findingID, cmd.ID.String())
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", w.Code)
			}
			if len(repo.rows) != 0 || fm.current.Status() != vulnerability.FindingStatusFixApplied {
				t.Fatal("rejected evidence must not be stored or applied")
			}
		})
	}
}

func TestValidationHandler_IngestEvidence_MalformedCommandID(t *testing.T) {
	h := newValidationHandler(&fakeEvidenceRepo{}, &fakeFindingMutator{current: fixAppliedFinding(t)})
	h.SetCommandLookup(&fakeCommandLookup{})
	w := postEvidence(t, h, shared.NewID(), shared.NewID(), shared.NewID(), "not-an-id")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
