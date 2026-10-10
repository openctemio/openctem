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
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// listedScans is routeScans that also lists every scan it holds, whatever
// the tenant: the service must keep only the caller's.
type listedScans struct{ routeScans }

func (f *listedScans) GovernanceScans(context.Context, shared.ID, int) ([]*scan.Scan, int, error) {
	out := make([]*scan.Scan, 0, len(f.scans))
	for _, sc := range f.scans {
		out = append(out, sc)
	}
	return out, len(out), nil
}

// The rule tester through the real routes (RFC-073 §4.3): owner or
// administrator only, invalid rules refused, and only the caller's
// organization's scans are evaluated; nothing is saved.
func TestScanRuleTester_Routes_DB(t *testing.T) {
	scans := &listedScans{routeScans{scans: map[string]*scan.Scan{}}}
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		pol := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), nil, nil, nil, nil, log)
		pol.SetSettings(ts)
		g := scangov.NewService(pol, ts, log)
		g.SetScans(scans)
		g.SetScanLister(scans)
		hs.ScanGovernance = handler.NewScanGovernanceHandler(g, log)
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t)
	org, other := h.tenant(), h.tenant()
	owner, admin, member := h.member(org, "owner"), h.member(org, "admin"), h.member(org, "member")
	mine, theirs := shared.NewID(), shared.NewID()
	orgID, _ := shared.IDFromString(org)
	otherID, _ := shared.IDFromString(other)
	scans.scans[mine.String()] = &scan.Scan{ID: mine, TenantID: orgID, Name: "mine"}
	scans.scans[theirs.String()] = &scan.Scan{ID: theirs, TenantID: otherID, Name: "theirs"}
	const url = "/api/v1/organization/settings/scan-governance/test"
	body := `{"rules":[{"name":"Intrusive","enabled":true,"conditions":{"min_intensity":"intrusive"},"requirement":{"approvals":1}}]}`

	h.expect(member, http.MethodPost, url, body, http.StatusForbidden)
	h.expect(admin, http.MethodPost, url, `{"rules":[{"name":"","enabled":true,"requirement":{"approvals":1}}]}`, http.StatusBadRequest)
	h.expect(admin, http.MethodPost, url, `{"rules":[],"extra":1}`, http.StatusBadRequest)
	var out struct {
		Mode   string `json:"mode"`
		Tested int    `json:"tested"`
		Caught int    `json:"caught"`
		Scans  []struct {
			ScanID string `json:"scan_id"`
		} `json:"scans"`
	}
	if err := json.Unmarshal([]byte(h.expect(owner, http.MethodPost, url, body, http.StatusOK)), &out); err != nil {
		t.Fatal(err)
	}
	if out.Mode != "on" || out.Tested != 1 || out.Caught != 1 || len(out.Scans) != 1 || out.Scans[0].ScanID != mine.String() {
		t.Fatalf("tester result %+v: want only this organization's scan, Off tested as On", out)
	}
	st := settingsOf(t, h.expect(member, http.MethodGet, "/api/v1/organization/settings/scan-governance", "", http.StatusOK))
	if rules, _ := st["rules"].([]any); len(rules) != 0 {
		t.Fatalf("the tester saved rules: %v", st)
	}
}
