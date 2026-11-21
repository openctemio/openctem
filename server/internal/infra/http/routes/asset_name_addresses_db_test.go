package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type nameAddressesBody struct {
	Items []struct {
		Address  string `json:"address"`
		Provider string `json:"provider"`
		Current  bool   `json:"current"`
		Sources  []struct {
			Name string `json:"name"`
		} `json:"sources"`
	} `json:"items"`
}

// GET /assets/{id}/addresses (research/531): a name's address history is
// read in the caller's data scope (out of scope answers 404), never another
// tenant's, and carries the provider of a shared address.
func TestNameAddresses_DataScopeAndTenant(t *testing.T) {
	h := newDSHarness(t)
	ten := h.tenant.String()
	h.exec(`INSERT INTO asset_attribute_set_elements (tenant_id, asset_id, attribute, source_kind, source_name, element, first_seen, last_seen, removed_at)
		VALUES ($1, $2, 'ip_addresses', 'scan', 'dnsx', '13.107.128.10', now() - interval '3 days', now(), NULL),
		       ($1, $2, 'ip_addresses', 'scan', 'dnsx', '3.11.53.20', now() - interval '9 days', now() - interval '5 days', now() - interval '4 days'),
		       ($1, $3, 'ip_addresses', 'scan', 'dnsx', '203.0.113.99', now(), now(), NULL)`,
		ten, h.assetA.String(), h.assetB.String())

	// Another tenant: a name with its own history.
	other, oname := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "nax-"+other.String())
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
		oname.String(), other.String(), dsMarkerAssetA)
	h.exec(`INSERT INTO asset_attribute_set_elements (tenant_id, asset_id, attribute, source_kind, source_name, element, first_seen, last_seen)
		VALUES ($1, $2, 'ip_addresses', 'scan', 'dnsx', '198.51.100.250', now(), now())`, other.String(), oname.String())

	path := "/api/v1/assets/" + h.assetA.String() + "/addresses"
	code, body := h.do(h.memberA, false, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("member: %d %s", code, body)
	}
	var got nameAddressesBody
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 2 || got.Items[0].Address != "13.107.128.10" || !got.Items[0].Current ||
		got.Items[0].Provider != "Microsoft 365" || got.Items[1].Current || got.Items[1].Provider != "Amazon CloudFront" {
		t.Fatalf("history: %s", body)
	}
	if strings.Contains(body, "203.0.113.99") || strings.Contains(body, "198.51.100.250") {
		t.Fatalf("another asset's or tenant's address listed: %s", body)
	}

	// A name outside the member's scope, and another tenant's name, are not found.
	if code, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/assets/"+h.assetB.String()+"/addresses", nil); code != http.StatusNotFound {
		t.Fatalf("out-of-scope name: %d %s", code, body)
	}
	if code, body := h.do(h.owner, true, http.MethodGet, "/api/v1/assets/"+oname.String()+"/addresses", nil); code != http.StatusNotFound {
		t.Fatalf("foreign name: %d %s", code, body)
	}
}
