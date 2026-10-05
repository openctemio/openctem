package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeAttrReader struct {
	view  *postgres.AttributionView
	found bool
	asked shared.ID
}

func (f *fakeAttrReader) Get(_ context.Context, tenantID shared.ID, _ string) (*postgres.AttributionView, bool, error) {
	f.asked = tenantID
	return f.view, f.found, nil
}

func (f *fakeAttrReader) SaveDecision(_ context.Context, tenantID shared.ID, _ string, st attribution.State, _ string) (bool, error) {
	f.asked = tenantID
	f.found = true
	if f.view == nil {
		f.view = &postgres.AttributionView{}
	}
	f.view.Record = attribution.Record{State: st, HumanDecided: true}
	return true, nil
}

type fakeAuditor struct{ events []auditapp.AuditEvent }

func (a *fakeAuditor) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}

type fakeScopedAssets struct{ err error }

func (f fakeScopedAssets) GetAssetWithScope(context.Context, string, string, string, bool) (*assetdom.Asset, error) {
	return nil, f.err
}

func getAttribution(t *testing.T, h *AssetAttributionHandler, tenant shared.ID) (*httptest.ResponseRecorder, AssetAttributionResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets/x/attribution", nil)
	req.SetPathValue("id", shared.NewID().String())
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String()))
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	var body AssetAttributionResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func TestAssetAttributionHandler(t *testing.T) {
	tenant := shared.NewID()

	// Legacy asset: no record means confirmed, scans allowed.
	h := NewAssetAttributionHandler(&fakeAttrReader{view: &postgres.AttributionView{}}, fakeScopedAssets{}, logger.NewNop())
	rec, body := getAttribution(t, h, tenant)
	if rec.Code != http.StatusOK || body.State != "confirmed" || body.Recorded || !body.ActiveChecksAllowed {
		t.Fatalf("legacy: %d %+v", rec.Code, body)
	}

	// A CT name under an unverified domain: needs review, scans blocked.
	reader := &fakeAttrReader{found: true, view: &postgres.AttributionView{
		Record:   attribution.Record{State: attribution.StateNeedsReview, Confidence: 85, Reason: attribution.RuleAssertedRoot},
		Evidence: []postgres.EvidenceView{{Rule: attribution.RuleAssertedRoot, Technique: "cert_transparency", Source: "crt.sh", Weight: 0.85}},
	}}
	h = NewAssetAttributionHandler(reader, fakeScopedAssets{}, logger.NewNop())
	rec, body = getAttribution(t, h, tenant)
	if rec.Code != http.StatusOK || body.State != "needs_review" || body.Confidence != 85 || body.ActiveChecksAllowed || len(body.Evidence) != 1 {
		t.Fatalf("needs_review: %d %+v", rec.Code, body)
	}
	if reader.asked != tenant {
		t.Fatalf("read under tenant %s, want %s", reader.asked, tenant)
	}

	// An asset outside the caller's tenant or data scope is a 404, and the
	// attribution is never read.
	reader = &fakeAttrReader{}
	h = NewAssetAttributionHandler(reader, fakeScopedAssets{err: shared.ErrNotFound}, logger.NewNop())
	if rec, _ := getAttribution(t, h, tenant); rec.Code != http.StatusNotFound || !reader.asked.IsZero() {
		t.Fatalf("out of scope: %d, read=%v", rec.Code, !reader.asked.IsZero())
	}
}

func putAttribution(t *testing.T, h *AssetAttributionHandler, tenant shared.ID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/assets/x/attribution", strings.NewReader(body))
	req.SetPathValue("id", shared.NewID().String())
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String()))
	rec := httptest.NewRecorder()
	h.Decide(rec, req)
	return rec
}

// A person confirms or rejects; the decision is audited, and invalid or
// automation-only states are refused.
func TestAssetAttributionHandler_Decide(t *testing.T) {
	tenant := shared.NewID()
	reader := &fakeAttrReader{found: true, view: &postgres.AttributionView{Record: attribution.Record{State: attribution.StateNeedsReview, Confidence: 85}}}
	audit := &fakeAuditor{}
	h := NewAssetAttributionHandler(reader, fakeScopedAssets{}, logger.NewNop())
	h.SetAuditService(audit)

	rec := putAttribution(t, h, tenant, `{"state":"confirmed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	var body AssetAttributionResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.State != "confirmed" || !body.HumanDecided || !body.ActiveChecksAllowed {
		t.Fatalf("after confirm: %+v", body)
	}
	if len(audit.events) != 1 || audit.events[0].Metadata["from"] != "needs_review" || audit.events[0].Metadata["to"] != "confirmed" {
		t.Fatalf("audit = %+v", audit.events)
	}

	for _, bad := range []string{`{"state":"candidate"}`, `{"state":"owned"}`, `{`} {
		if rec := putAttribution(t, h, tenant, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d", bad, rec.Code)
		}
	}

	out := &fakeAttrReader{}
	h = NewAssetAttributionHandler(out, fakeScopedAssets{err: shared.ErrForbidden}, logger.NewNop())
	if rec := putAttribution(t, h, tenant, `{"state":"confirmed"}`); rec.Code != http.StatusNotFound || out.found {
		t.Fatalf("out-of-scope decision: %d, saved=%v", rec.Code, out.found)
	}
}

type fakeActiveGate struct {
	state attribution.State
	err   error
	asked shared.ID
}

func (g *fakeActiveGate) ActiveCheckBlocked(_ context.Context, tenantID shared.ID, ids []string) (map[string]attribution.State, error) {
	g.asked = tenantID
	if g.err != nil {
		return nil, g.err
	}
	out := map[string]attribution.State{}
	if g.state != "" {
		out[ids[0]] = g.state
	}
	return out, nil
}

// active_checks_allowed answers with the scans' own gate: a legacy asset
// outside every scope target is reported as not scannable, with the reason;
// a failed lookup reports not scannable.
func TestAssetAttributionHandler_ActiveGate(t *testing.T) {
	tenant := shared.NewID()
	h := NewAssetAttributionHandler(&fakeAttrReader{view: &postgres.AttributionView{}}, fakeScopedAssets{}, logger.NewNop())
	gate := &fakeActiveGate{state: attribution.StateUnattributed}
	h.SetActiveGate(gate)
	_, body := getAttribution(t, h, tenant)
	if body.ActiveChecksAllowed || body.ActiveChecksBlockedBy != "unattributed" || !gate.asked.Equals(tenant) {
		t.Fatalf("unattributed: %+v (asked %s)", body, gate.asked)
	}
	gate.state = ""
	if _, body := getAttribution(t, h, tenant); !body.ActiveChecksAllowed || body.ActiveChecksBlockedBy != "" {
		t.Fatalf("allowed: %+v", body)
	}
	gate.err = context.DeadlineExceeded
	if _, body := getAttribution(t, h, tenant); body.ActiveChecksAllowed {
		t.Fatalf("a failed gate lookup reported scannable: %+v", body)
	}
}
