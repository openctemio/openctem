package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type resolvedPortsBody struct {
	Items []struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		Service string `json:"service"`
		Product string `json:"product"`
	} `json:"items"`
	HiddenCount int64 `json:"hidden_count"`
	Truncated   bool  `json:"truncated"`
}

// rpFixture: asset A1 (in memberA's scope) resolves to two addresses. The
// first is in memberA's scope and exposes 8443 (in scope) and 22 (out of
// scope); the second is out of scope and exposes 9443. A closed port, and
// another tenant's name of the same spelling, are never listed.
type rpFixture struct {
	ipIn, ipOut, ipForeign shared.ID
}

func (h *dsHarness) seedResolvedPorts() rpFixture {
	h.t.Helper()
	t := h.tenant.String()
	f := rpFixture{ipIn: shared.NewID(), ipOut: shared.NewID(), ipForeign: shared.NewID()}
	pIn, pHidden, pOut, pClosed := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES
		($1, $3, '203.0.113.10', 'ip_address', 'public', 'high'),
		($2, $3, '203.0.113.20', 'ip_address', 'public', 'high')`, f.ipIn.String(), f.ipOut.String(), t)
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, exposure, criticality, status, properties) VALUES
		($1, $5, '203.0.113.10:8443:tcp', 'service', 'open_port', 'public', 'high', 'active', '{"port": 8443, "protocol": "tcp", "service": "https", "product": "rp-nginx"}'),
		($2, $5, '203.0.113.10:22:tcp', 'service', 'open_port', 'public', 'high', 'active', '{"port": 22, "protocol": "tcp", "service": "rp-HIDDEN-ssh"}'),
		($3, $5, '203.0.113.20:9443:tcp', 'service', 'open_port', 'public', 'high', 'active', '{"port": 9443, "protocol": "tcp", "service": "rp-HIDDEN-out"}'),
		($4, $5, '203.0.113.10:8080:tcp', 'service', 'open_port', 'public', 'high', 'inactive', '{"port": 8080, "protocol": "tcp", "service": "rp-CLOSED"}')`,
		pIn.String(), pHidden.String(), pOut.String(), pClosed.String(), t)
	a1 := h.assetA.String()
	h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES
		($1, $2, $3, 'resolves_to'), ($1, $2, $4, 'resolves_to'),
		($1, $3, $5, 'exposes'), ($1, $3, $6, 'exposes'), ($1, $4, $7, 'exposes'), ($1, $3, $8, 'exposes')`,
		t, a1, f.ipIn.String(), f.ipOut.String(), pIn.String(), pHidden.String(), pOut.String(), pClosed.String())
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES
		($1, $2, $3, 'secondary'), ($1, $2, $4, 'secondary')`, h.memberA.String(), t, f.ipIn.String(), pIn.String())

	// Another tenant has a name of the same spelling that resolves to its own
	// address and port (an edge across tenants is refused by the schema's
	// tenant-bound foreign keys).
	other, fname, fport := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "rpx-"+other.String())
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES
		($1, $3, $4, 'domain', 'public', 'high'), ($2, $3, '198.51.100.7', 'ip_address', 'public', 'high')`,
		fname.String(), f.ipForeign.String(), other.String(), dsMarkerAssetA)
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, exposure, criticality, properties) VALUES
		($1, $2, '198.51.100.7:3389:tcp', 'service', 'open_port', 'public', 'high', '{"port": 3389, "service": "rpX-FOREIGN"}')`,
		fport.String(), other.String())
	h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES
		($1, $2, $3, 'resolves_to'), ($1, $3, $4, 'exposes')`, other.String(), fname.String(), f.ipForeign.String(), fport.String())
	return f
}

func decodeResolvedPorts(t *testing.T, body string) resolvedPortsBody {
	t.Helper()
	var b resolvedPortsBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatalf("resolved ports body: %v: %.300s", err, body)
	}
	return b
}

func TestResolvedPorts_PerRowDataScopeAndTenant(t *testing.T) {
	h := newDSHarness(t)
	h.seedResolvedPorts()
	path := "/api/v1/assets/" + h.assetA.String() + "/resolved-ports"

	// The owner sees every live port of both addresses, by address then port.
	code, body := h.do(h.owner, true, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("owner: %d %s", code, body)
	}
	got := decodeResolvedPorts(t, body)
	var seen []string
	for _, it := range got.Items {
		seen = append(seen, it.Address+":"+strconv.Itoa(it.Port))
	}
	if strings.Join(seen, ",") != "203.0.113.10:22,203.0.113.10:8443,203.0.113.20:9443" || got.HiddenCount != 0 {
		t.Fatalf("owner rows %v hidden %d", seen, got.HiddenCount)
	}
	if strings.Contains(body, "rp-CLOSED") || strings.Contains(body, "rpX-FOREIGN") || strings.Contains(body, "198.51.100.7") {
		t.Fatalf("closed or cross-tenant port listed: %s", body)
	}

	// memberA sees only the row whose address and port are both in scope;
	// the other two are counted, never named.
	code, body = h.do(h.memberA, false, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("member: %d %s", code, body)
	}
	got = decodeResolvedPorts(t, body)
	if len(got.Items) != 1 || got.Items[0].Port != 8443 || got.Items[0].Product != "rp-nginx" || got.HiddenCount != 2 {
		t.Fatalf("member: %+v", got)
	}
	if strings.Contains(body, "rp-HIDDEN") || strings.Contains(body, "203.0.113.20") {
		t.Fatalf("member saw an out-of-scope port: %s", body)
	}
}

func TestResolvedPorts_OutOfScopeNameAndOtherTypes(t *testing.T) {
	h := newDSHarness(t)
	f := h.seedResolvedPorts()

	// A name outside the member's scope is not found (the route guard).
	code, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/assets/"+h.assetB.String()+"/resolved-ports", nil)
	if code != http.StatusNotFound {
		t.Fatalf("out-of-scope name: %d %s", code, body)
	}
	// Another tenant's address is not found either.
	code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets/"+f.ipForeign.String()+"/resolved-ports", nil)
	if code != http.StatusNotFound {
		t.Fatalf("foreign asset: %d %s", code, body)
	}
	// An address is not a name: an empty list, not its own ports.
	code, body = h.do(h.owner, true, http.MethodGet, "/api/v1/assets/"+f.ipIn.String()+"/resolved-ports", nil)
	if code != http.StatusOK || len(decodeResolvedPorts(t, body).Items) != 0 {
		t.Fatalf("address: %d %s", code, body)
	}
}

// The asset view carries the resolved ports as a part, exactly as the caller
// reads them directly, and a name outside the caller's scope yields only the
// asset's refusal.
func TestAssetView_PartsAreTheCallersOwnReads(t *testing.T) {
	h := newDSHarness(t)
	h.seedResolvedPorts()
	a := "/api/v1/assets/" + h.assetA.String()

	code, body := h.do(h.memberA, false, http.MethodGet, a+"/view", nil)
	if code != http.StatusOK {
		t.Fatalf("view: %d %s", code, body)
	}
	view := decodeFindingView(t, body)
	for _, part := range []string{a, a + "/resolved-ports"} {
		p, ok := view.Parts[part]
		if !ok {
			t.Fatalf("part %s missing: %v", part, view.Parts)
		}
		directCode, direct := h.do(h.memberA, false, http.MethodGet, part, nil)
		if p.Status != directCode || strings.TrimSpace(string(p.Body)) != strings.TrimSpace(direct) {
			t.Errorf("%s: view %d %.200s, direct %d %.200s", part, p.Status, p.Body, directCode, direct)
		}
	}
	if strings.Contains(body, "rp-HIDDEN") || strings.Contains(body, dsMarkerAssetB) {
		t.Errorf("view leaked out-of-scope data: %.400s", body)
	}

	b := "/api/v1/assets/" + h.assetB.String()
	code, body = h.do(h.memberA, false, http.MethodGet, b+"/view", nil)
	directCode, direct := h.do(h.memberA, false, http.MethodGet, b, nil)
	if code != http.StatusNotFound || code != directCode || strings.TrimSpace(body) != strings.TrimSpace(direct) {
		t.Fatalf("out-of-scope view %d %s, direct %d %s: want the same 404", code, body, directCode, direct)
	}
}

func TestAssetView_NeedsAssetsRead(t *testing.T) {
	h := newDSHarness(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		h.srv.URL+"/api/v1/assets/"+h.assetA.String()+"/view", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", h.memberA.String())
	req.Header.Set("X-Test-Perms", "findings:read")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
}
