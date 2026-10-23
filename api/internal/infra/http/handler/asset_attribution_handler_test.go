package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"
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

type visibleAssets struct{ visible map[string]bool }

func (v visibleAssets) GetAssetWithScope(_ context.Context, _, id, _ string, _ bool) (*assetdom.Asset, error) {
	if v.visible[id] {
		return nil, nil
	}
	return nil, shared.ErrNotFound
}

type fakeCertStandings struct{ st easmapp.CertStanding }

func (f fakeCertStandings) CertificateStandings(_ context.Context, _ shared.ID, ids []shared.ID) (map[string]easmapp.CertStanding, error) {
	return map[string]easmapp.CertStanding{ids[0].String(): f.st}, nil
}

// A certificate's standing names only the endpoints the caller may see: the
// ones outside the caller's data scope are dropped from the list and left
// unnamed where the standing points at them. The standing itself stays.
func TestAssetAttributionHandler_CertificateStandingFollowsDataScope(t *testing.T) {
	tenant := shared.NewID()
	mine, hidden := shared.NewID().String(), shared.NewID().String()
	st := easmapp.CertStanding{
		Standing:      easmapp.CertStandingInScope,
		ServedBy:      &scopeauth.Via{Kind: scopeauth.KindServedBy, Endpoint: hidden, Name: "secret.example.com:443", Pattern: "*.example.com"},
		Endpoints:     []easmapp.CertEndpoint{{AssetID: mine, Name: "a.example.com:443"}, {AssetID: hidden, Name: "secret.example.com:443"}},
		EndpointCount: 2,
		Ownership:     easmapp.CertOwnershipYours,
	}
	h := NewAssetAttributionHandler(&fakeAttrReader{view: &postgres.AttributionView{}}, visibleAssets{visible: map[string]bool{mine: true}}, logger.NewNop())
	h.SetCertificateReader(fakeCertStandings{st: st})
	var resp AssetAttributionResponse
	h.applyCertificate(context.Background(), tenant, shared.NewID().String(), &resp)
	c := resp.Certificate
	if c == nil || c.Standing != easmapp.CertStandingInScope || c.EndpointCount != 2 {
		t.Fatalf("certificate = %+v", c)
	}
	if len(c.Endpoints) != 1 || c.Endpoints[0].AssetID != mine {
		t.Errorf("endpoints = %+v", c.Endpoints)
	}
	if c.ServedBy == nil || c.ServedBy.Endpoint != "" || c.ServedBy.Name != "" || c.ServedBy.Pattern != "*.example.com" {
		t.Errorf("served_by = %+v", c.ServedBy)
	}
	raw, _ := json.Marshal(resp)
	if strings.Contains(string(raw), "secret.example.com") || strings.Contains(string(raw), hidden) {
		t.Errorf("a hidden endpoint leaked: %s", raw)
	}
}

type hiddenAssets struct{ hidden string }

func (v hiddenAssets) GetAssetWithScope(_ context.Context, _, id, _ string, _ bool) (*assetdom.Asset, error) {
	if id == v.hidden {
		return nil, shared.ErrNotFound
	}
	return nil, nil
}

type fakeScopeVia struct{ via *scopeauth.Via }

func (f fakeScopeVia) ScopeOfAsset(context.Context, shared.ID, string) (string, *scopeauth.Via, error) {
	return "in_scope", f.via, nil
}

// covered_by names the serving endpoint only when the caller may see it: the
// scope reader's unfiltered answer must not leak a hidden endpoint's id or
// name, on the read and on the decision.
func TestAssetAttributionHandler_CoveredByHidesHiddenEndpoint(t *testing.T) {
	tenant := shared.NewID()
	mine, hidden := shared.NewID().String(), shared.NewID().String()
	build := func(servedBy string) *AssetAttributionHandler {
		via := &scopeauth.Via{Kind: scopeauth.KindServedBy, Endpoint: servedBy, Name: "secret.example.com:443", Pattern: "*.example.com"}
		st := easmapp.CertStanding{Standing: easmapp.CertStandingInScope, ServedBy: via, EndpointCount: 1,
			Endpoints: []easmapp.CertEndpoint{{AssetID: servedBy, Name: "secret.example.com:443"}}}
		h := NewAssetAttributionHandler(&fakeAttrReader{found: true, view: &postgres.AttributionView{}}, hiddenAssets{hidden: hidden}, logger.NewNop())
		h.SetCertificateReader(fakeCertStandings{st: st})
		h.SetScopeReader(fakeScopeVia{via: via})
		h.SetActiveGate(&fakeActiveGate{})
		return h
	}
	h := build(hidden)
	rec, _ := getAttribution(t, h, tenant)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	rec2 := putAttribution(t, h, tenant, `{"state":"confirmed"}`)
	if rec2.Code != http.StatusOK {
		t.Fatalf("decide: %d %s", rec2.Code, rec2.Body)
	}
	for name, raw := range map[string]string{"get": rec.Body.String(), "decide": rec2.Body.String()} {
		if strings.Contains(raw, "secret.example.com") || strings.Contains(raw, hidden) {
			t.Errorf("%s leaked a hidden endpoint: %s", name, raw)
		}
		if !strings.Contains(raw, `"covered_by"`) || !strings.Contains(raw, "*.example.com") {
			t.Errorf("%s lost covered_by: %s", name, raw)
		}
	}
	// A visible endpoint stays named.
	rec, _ = getAttribution(t, build(mine), tenant)
	if !strings.Contains(rec.Body.String(), mine) {
		t.Errorf("visible endpoint dropped: %s", rec.Body)
	}
}
