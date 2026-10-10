package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scangov"
	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scangovdom "github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// routeScans answers the scans the test inserted (an intrusive scanner).
type routeScans struct{ scans map[string]*scan.Scan }

func (f *routeScans) GovernanceSubject(_ context.Context, t, id shared.ID) (*scan.Scan, scangovdom.Definition, scangovdom.Facts, error) {
	sc, ok := f.scans[id.String()]
	if !ok || sc.TenantID != t {
		return nil, scangovdom.Definition{}, scangovdom.Facts{}, shared.ErrNotFound
	}
	d, fa, _ := f.GovernanceSubjectOf(context.Background(), sc)
	return sc, d, fa, nil
}

func (f *routeScans) GovernanceSubjectOf(_ context.Context, sc *scan.Scan) (scangovdom.Definition, scangovdom.Facts, error) {
	return scangovdom.Definition{Targets: sc.Targets, ScanType: "single", ScannerName: "zap", Intensity: "intrusive"},
		scangovdom.Facts{IntensityTier: 2, WidestCIDRPrefix: -1}, nil
}

func (f *routeScans) RunApproved(context.Context, shared.ID, shared.ID, string) error { return nil }

// Scan approval requests through the real routes and database (RFC-072
// §8): a member submits, an administrator approves, the requester never
// approves, a member without scans:approve cannot decide, reminders are
// rate-limited, and another organization reaches nothing (404).
func TestScanApprovals_Routes_DB(t *testing.T) {
	scans := &routeScans{scans: map[string]*scan.Scan{}}
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		pol := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), nil, nil, nil, nil, log)
		pol.SetSettings(ts)
		repo := postgres.NewScanApprovalRepository(db)
		g := scangov.NewService(pol, ts, log)
		g.SetRequests(repo)
		g.SetApprovers(repo, nil)
		g.SetScans(scans)
		sh := handler.NewScanHandler(nil, nil, nil, validator.New(), log)
		sh.SetApprovals(handler.NewScanApprovalHandler(g, log))
		hs.Scan = sh
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t)
	org, other := h.tenant(), h.tenant()
	owner, admin, member := h.member(org, "owner"), h.member(org, "admin"), h.member(org, "member")
	otherOwner := h.member(other, "owner")
	h.exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{scan_governance}',
		'{"mode":"on","rules":[{"id":"6b1f5d1e-6a8e-4f53-9d5a-1f3e1b2c3d4e","name":"Intrusive scans","enabled":true,"conditions":{"min_intensity":"intrusive"},"requirement":{"approvals":1}}]}') WHERE id = $1`, org)

	newScan := func(tid string) string {
		id := shared.NewID()
		tidID, _ := shared.IDFromString(tid)
		h.exec(`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets) VALUES ($1::uuid, $2, 'web pentest ' || $1::text, 'single', 'zap', ARRAY['app.acme.vn'])`, id.String(), tid)
		scans.scans[id.String()] = &scan.Scan{ID: id, TenantID: tidID, Name: "web pentest", Targets: []string{"app.acme.vn"}}
		return id.String()
	}
	s1, s2, s3 := newScan(org), newScan(org), newScan(other)

	st := settingsOf(t, h.expect(member, http.MethodGet, "/api/v1/scans/"+s1+"/approval", "", http.StatusOK))
	if st["required"] != true || st["approved"] != false {
		t.Fatalf("status before: %v", st)
	}
	req := settingsOf(t, h.expect(member, http.MethodPost, "/api/v1/scans/"+s1+"/approval", `{"justification":"quarterly"}`, http.StatusCreated))
	id, _ := req["id"].(string)
	if req["status"] != "pending" || req["remaining"] != float64(1) {
		t.Fatalf("submitted: %v", req)
	}
	base := "/api/v1/scan-approvals/" + id
	h.expect(member, http.MethodPost, base+"/approve", `{}`, http.StatusForbidden) // no scans:approve
	h.expect(otherOwner, http.MethodGet, base, "", http.StatusNotFound)
	h.expect(otherOwner, http.MethodPost, base+"/approve", `{}`, http.StatusNotFound)
	h.expect(member, http.MethodPost, base+"/remind", "", http.StatusOK)
	h.expect(member, http.MethodPost, base+"/remind", "", http.StatusTooManyRequests)

	var list struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	_ = json.Unmarshal([]byte(h.expect(otherOwner, http.MethodGet, "/api/v1/scan-approvals?status=pending", "", http.StatusOK)), &list)
	if list.Total != 0 {
		t.Fatalf("another organization lists %d requests", list.Total)
	}
	_ = json.Unmarshal([]byte(h.expect(admin, http.MethodGet, "/api/v1/scan-approvals?status=pending", "", http.StatusOK)), &list)
	if list.Total != 1 || list.Data[0]["can_approve"] != true {
		t.Fatalf("inbox: %+v", list)
	}

	got := settingsOf(t, h.expect(admin, http.MethodPost, base+"/approve", `{"note":"ok"}`, http.StatusOK))
	if got["status"] != "approved" {
		t.Fatalf("approved: %v", got)
	}
	st = settingsOf(t, h.expect(member, http.MethodGet, "/api/v1/scans/"+s1+"/approval", "", http.StatusOK))
	if st["approved"] != true {
		t.Fatalf("status after: %v", st)
	}

	// The requester never approves their own request.
	own := settingsOf(t, h.expect(owner, http.MethodPost, "/api/v1/scans/"+s2+"/approval", `{"justification":"x"}`, http.StatusCreated))
	code, body := h.do(owner, http.MethodPost, "/api/v1/scan-approvals/"+own["id"].(string)+"/approve", `{}`)
	if code != http.StatusForbidden || !jsonHas(body, "code", "SCAN_APPROVAL_OWN_REQUEST") {
		t.Fatalf("self approve: %d %s", code, body)
	}

	// Another organization's scan is not found; Off needs no approval.
	h.expect(owner, http.MethodPost, "/api/v1/scans/"+s3+"/approval", `{"justification":"x"}`, http.StatusNotFound)
	code, body = h.do(otherOwner, http.MethodPost, "/api/v1/scans/"+s3+"/approval", `{"justification":"x"}`)
	if code != http.StatusBadRequest || !jsonHas(body, "code", "SCAN_APPROVAL_OFF") {
		t.Fatalf("Off: %d %s", code, body)
	}
}
