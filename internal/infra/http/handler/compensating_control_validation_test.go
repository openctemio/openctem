package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/compensatingcontrol"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// newControlHandlerNoDB builds the handler with a nil *sql.DB on purpose.
//
// Every case below must be rejected by validation BEFORE the handler reaches
// the database. If a regression lets one through, the nil DB panics the test
// instead of quietly turning a CHECK violation back into a 500.
func newControlHandlerNoDB() *CompensatingControlHandler {
	return NewCompensatingControlHandler(nil, logger.NewNop())
}

// TestCompensatingControl_Create_RejectsValuesTheDatabaseWouldRefuse is the
// regression guard for the defect that made this feature unusable: the create
// form sent control_type values and a percentage reduction_factor that no row
// could ever hold, so every create hit a CHECK violation and came back as a
// generic 500.
func TestCompensatingControl_Create_RejectsValuesTheDatabaseWouldRefuse(t *testing.T) {
	tenantID := shared.NewID()

	cases := []struct {
		name     string
		body     string
		wantText string
	}{
		{
			// The exact payload the UI used to send: control_type from a
			// vocabulary with ZERO overlap with the CHECK constraint, and a
			// reduction_factor expressed as a percent.
			name:     "legacy UI payload",
			body:     `{"name":"WAF Rate Limiting","control_type":"compensating","reduction_factor":20}`,
			wantText: "control_type must be one of",
		},
		{
			name:     "other legacy control types",
			body:     `{"name":"c","control_type":"preventive","reduction_factor":0.2}`,
			wantText: "control_type must be one of",
		},
		{
			name:     "empty control type",
			body:     `{"name":"c","reduction_factor":0.2}`,
			wantText: "control_type must be one of",
		},
		{
			// 20 was the old default and is 20x above the CHECK ceiling.
			name:     "reduction factor as percent",
			body:     `{"name":"c","control_type":"runtime","reduction_factor":20}`,
			wantText: "reduction_factor must be a fraction",
		},
		{
			name:     "reduction factor above 1",
			body:     `{"name":"c","control_type":"runtime","reduction_factor":1.5}`,
			wantText: "reduction_factor must be a fraction",
		},
		{
			// Accepted by the CHECK (it allows >= 0) but a no-op for scoring,
			// so it is refused rather than silently stored.
			name:     "zero reduction factor is a silent no-op",
			body:     `{"name":"c","control_type":"runtime","reduction_factor":0}`,
			wantText: "reduction_factor must be a fraction",
		},
		{
			name:     "negative reduction factor",
			body:     `{"name":"c","control_type":"runtime","reduction_factor":-0.5}`,
			wantText: "reduction_factor must be a fraction",
		},
		{
			name:     "unknown status",
			body:     `{"name":"c","control_type":"runtime","status":"pending","reduction_factor":0.2}`,
			wantText: "status must be one of",
		},
		{
			name:     "missing name",
			body:     `{"control_type":"runtime","reduction_factor":0.2}`,
			wantText: "name is required",
		},
		{
			name:     "blank name",
			body:     `{"name":"   ","control_type":"runtime","reduction_factor":0.2}`,
			wantText: "name is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newControlHandlerNoDB()
			w := httptest.NewRecorder()

			h.Create(w, requestWithTenant("POST", "/api/v1/compensating-controls/", tc.body, tenantID))

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (a client input mistake must not look like a server fault); body: %s",
					w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantText) {
				t.Fatalf("body %q should explain the problem and contain %q", w.Body.String(), tc.wantText)
			}
		})
	}
}

// TestCompensatingControl_Update_RejectsSameValues — Update writes the same
// columns, so it must enforce the same vocabulary.
func TestCompensatingControl_Update_RejectsSameValues(t *testing.T) {
	h := newControlHandlerNoDB()
	w := httptest.NewRecorder()

	h.Update(w, requestWithTenant("PUT", "/api/v1/compensating-controls/x",
		`{"name":"c","control_type":"compensating","reduction_factor":20}`, shared.NewID()))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

// TestCompensatingControl_RecordTest_RejectsUnknownResult — an empty or unknown
// test_result violates the test_result CHECK and used to surface as a 500.
func TestCompensatingControl_RecordTest_RejectsUnknownResult(t *testing.T) {
	for _, body := range []string{`{}`, `{"test_result":""}`, `{"test_result":"passed"}`} {
		h := newControlHandlerNoDB()
		w := httptest.NewRecorder()

		h.RecordTest(w, requestWithTenant("POST", "/api/v1/compensating-controls/x/test", body, shared.NewID()))

		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400; got %s", body, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "test_result must be one of") {
			t.Fatalf("body %s: unhelpful error %q", body, w.Body.String())
		}
	}
}

// TestCompensatingControlVocabulary_MatchesDatabaseCheckConstraints pins the
// accepted vocabulary to the literal values in the CHECK constraints.
//
// If someone widens the domain enums without a migration, this fails here
// rather than as a 500 in production.
func TestCompensatingControlVocabulary_MatchesDatabaseCheckConstraints(t *testing.T) {
	// Copied verbatim from migrations/000146_compensating_controls.up.sql.
	wantTypes := []string{"segmentation", "identity", "runtime", "detection", "other"}
	wantStatuses := []string{"active", "inactive", "expired", "untested"}
	wantResults := []string{"pass", "fail", "partial"}

	gotTypes := make([]string, 0, len(wantTypes))
	for _, v := range compensatingcontrol.AllControlTypes() {
		gotTypes = append(gotTypes, string(v))
	}
	gotStatuses := make([]string, 0, len(wantStatuses))
	for _, v := range compensatingcontrol.AllControlStatuses() {
		gotStatuses = append(gotStatuses, string(v))
	}
	gotResults := make([]string, 0, len(wantResults))
	for _, v := range compensatingcontrol.AllTestResults() {
		gotResults = append(gotResults, string(v))
	}

	assertSameSet(t, "control_type", gotTypes, wantTypes)
	assertSameSet(t, "status", gotStatuses, wantStatuses)
	assertSameSet(t, "test_result", gotResults, wantResults)
}

func assertSameSet(t *testing.T, field string, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s vocabulary drifted from the CHECK constraint:\n got: %v\nwant: %v\n"+
			"changing this set requires a migration that alters the CHECK", field, got, want)
	}
}
