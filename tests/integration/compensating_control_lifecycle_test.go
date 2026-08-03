package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// controlRequest builds a request carrying the tenant/user context the auth
// middleware would normally set, plus a chi route param for {id}.
func controlRequest(method, path, body string, tenantID shared.ID, id string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID.String())
	if id != "" {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	}
	return r.WithContext(ctx)
}

// TestCompensatingControlCheckConstraintsRejectLegacyUIPayload documents, against
// the real schema, WHY the create form could never work: the values it sent
// violate the live CHECK constraints. This is the ground truth the handler-side
// validation mirrors — if a migration ever widens the vocabulary, this test
// starts failing and tells you to widen the Go allowlist too.
func TestCompensatingControlCheckConstraintsRejectLegacyUIPayload(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	tenant := createTestTenant(t, db, "cc-checks")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM compensating_controls WHERE tenant_id = $1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
	})

	insert := func(controlType string, factor float64) error {
		_, err := db.Exec(
			`INSERT INTO compensating_controls (tenant_id, name, control_type, reduction_factor)
			 VALUES ($1, $2, $3, $4)`,
			tenant.String(), "__test-legacy", controlType, factor,
		)
		return err
	}

	// The exact pair the create dialog defaulted to.
	if err := insert("compensating", 20); err == nil {
		t.Fatal("the legacy UI payload must be rejected by the database; " +
			"if this now succeeds the CHECK constraints changed")
	}
	// Each half is independently fatal.
	if err := insert("compensating", 0.2); err == nil {
		t.Fatal("control_type 'compensating' is not in the CHECK constraint")
	} else if !strings.Contains(err.Error(), "control_type") {
		t.Fatalf("expected a control_type CHECK violation, got: %v", err)
	}
	// 20 is rejected by DECIMAL(3,2) itself (numeric field overflow) before the
	// CHECK is even evaluated; 0.9999 gets past the type and is caught by the
	// CHECK. Both are fatal to a percent-valued write.
	if err := insert("runtime", 20); err == nil {
		t.Fatal("reduction_factor 20 must not be storable in DECIMAL(3,2)")
	}
	if err := insert("runtime", 1.5); err == nil {
		t.Fatal("reduction_factor 1.5 is outside the 0..1 CHECK constraint")
	} else if !strings.Contains(err.Error(), "reduction_factor") {
		t.Fatalf("expected a reduction_factor CHECK violation, got: %v", err)
	}

	// And the value the fixed form now sends is accepted.
	if err := insert("runtime", 0.2); err != nil {
		t.Fatalf("the corrected payload must satisfy both CHECKs, got: %v", err)
	}
}

// TestCompensatingControlHandlerLifecycle drives the real handler against the
// real schema: a bad create is a 400 (not a 500), a good create persists, the
// asset link that actually feeds scoring works, and a failed test deactivates.
func TestCompensatingControlHandlerLifecycle(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	tenant := createTestTenant(t, db, "cc-lifecycle")
	assetID := createTestAsset(t, db, tenant, "__test-cc-asset")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM compensating_control_assets WHERE asset_id = $1`, assetID.String())
		_, _ = db.Exec(`DELETE FROM compensating_controls WHERE tenant_id = $1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id = $1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
	})

	h := handler.NewCompensatingControlHandler(db, logger.NewNop())

	// --- 1. The legacy payload is a 400 with a usable message, not a 500. ---
	w := httptest.NewRecorder()
	h.Create(w, controlRequest("POST", "/api/v1/compensating-controls/",
		`{"name":"WAF Rate Limiting","control_type":"compensating","reduction_factor":20}`,
		tenant, ""))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("legacy payload: status = %d, want 400 (was 500 via a CHECK violation); body: %s",
			w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "control_type must be one of") {
		t.Fatalf("the 400 must say what is wrong, got: %s", w.Body.String())
	}
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM compensating_controls WHERE tenant_id = $1`, tenant.String(),
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("a rejected create must not persist anything, found %d rows", count)
	}

	// --- 2. The payload the fixed form sends is created. ---
	w = httptest.NewRecorder()
	h.Create(w, controlRequest("POST", "/api/v1/compensating-controls/",
		`{"name":"WAF Rate Limiting","description":"blocks the exploit path",`+
			`"control_type":"runtime","reduction_factor":0.3}`, tenant, ""))

	if w.Code != http.StatusCreated {
		t.Fatalf("valid create: status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID              string  `json:"id"`
		ControlType     string  `json:"control_type"`
		Status          string  `json:"status"`
		ReductionFactor float64 `json:"reduction_factor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == "" {
		t.Fatal("create must return the new id")
	}
	if created.ControlType != "runtime" {
		t.Fatalf("control_type = %q, want runtime", created.ControlType)
	}
	// Stored as the fraction, NOT a percent — DECIMAL(3,2) rounds to 2 places.
	if created.ReductionFactor != 0.3 {
		t.Fatalf("reduction_factor = %v, want 0.3 (a fraction)", created.ReductionFactor)
	}
	if created.Status != "active" {
		t.Fatalf("status = %q, want active by default", created.Status)
	}

	// --- 3. Linking an asset — the ONLY thing that feeds scoring. ---
	w = httptest.NewRecorder()
	h.LinkAssets(w, controlRequest("POST",
		"/api/v1/compensating-controls/"+created.ID+"/assets",
		`{"asset_ids":["`+assetID.String()+`"]}`, tenant, created.ID))

	if w.Code != http.StatusNoContent {
		t.Fatalf("link assets: status = %d, want 204; body: %s", w.Code, w.Body.String())
	}

	// The lookup the priority classifier consumes now returns the factor.
	lookup := postgres.NewCompensatingControlLookupRepo(db)
	eff, err := lookup.GetEffectiveForAssets(context.Background(), tenant, []shared.ID{assetID})
	if err != nil {
		t.Fatalf("GetEffectiveForAssets: %v", err)
	}
	if eff[assetID] != 0.3 {
		t.Fatalf("effective reduction for the linked asset = %v, want 0.3 "+
			"(without this the control cannot affect priority)", eff[assetID])
	}

	// --- 4. An unknown test_result is a 400, not a 500. ---
	w = httptest.NewRecorder()
	h.RecordTest(w, controlRequest("POST",
		"/api/v1/compensating-controls/"+created.ID+"/test",
		`{"test_result":""}`, tenant, created.ID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty test_result: status = %d, want 400; body: %s", w.Code, w.Body.String())
	}

	// --- 5. A failed test deactivates the control AND drops it from scoring. ---
	w = httptest.NewRecorder()
	h.RecordTest(w, controlRequest("POST",
		"/api/v1/compensating-controls/"+created.ID+"/test",
		`{"test_result":"fail","test_evidence":"bypassed in retest"}`, tenant, created.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("record test: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var status, testResult string
	if err := db.QueryRow(
		`SELECT status, test_result FROM compensating_controls WHERE id = $1`, created.ID,
	).Scan(&status, &testResult); err != nil {
		t.Fatalf("reload control: %v", err)
	}
	if testResult != "fail" {
		t.Fatalf("test_result = %q, want fail", testResult)
	}
	if status != "inactive" {
		t.Fatalf("status = %q, want inactive — a failed control reported itself as active", status)
	}

	eff, err = lookup.GetEffectiveForAssets(context.Background(), tenant, []shared.ID{assetID})
	if err != nil {
		t.Fatalf("GetEffectiveForAssets after fail: %v", err)
	}
	if _, ok := eff[assetID]; ok {
		t.Fatal("a failed control must not keep protecting the asset")
	}
}

// TestCompensatingControlCreateRejectsZeroFactor — the column default is 0.0 and
// the classifier only treats an asset as protected when the factor is > 0, so a
// control stored with 0 would be a silent no-op. It is refused at create time.
func TestCompensatingControlCreateRejectsZeroFactor(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	tenant := createTestTenant(t, db, "cc-zero")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM compensating_controls WHERE tenant_id = $1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String())
	})

	h := handler.NewCompensatingControlHandler(db, logger.NewNop())
	w := httptest.NewRecorder()
	h.Create(w, controlRequest("POST", "/api/v1/compensating-controls/",
		`{"name":"no-op control","control_type":"other"}`, tenant, ""))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an omitted/zero reduction_factor; body: %s",
			w.Code, w.Body.String())
	}

	// Guard the premise: a 0 factor IS storable, so only the handler stops it.
	var ok bool
	if err := db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM pg_constraint
		   WHERE conrelid = 'compensating_controls'::regclass
		     AND conname = 'compensating_controls_reduction_factor_check')`,
	).Scan(&ok); err != nil && err != sql.ErrNoRows { //nolint:errorlint
		t.Fatalf("constraint probe: %v", err)
	}
	if !ok {
		t.Fatal("expected the reduction_factor CHECK to exist")
	}
}
