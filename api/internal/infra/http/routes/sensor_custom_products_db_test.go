package routes

// An organization's own sensor products end to end (docs/rfcs/RFC-037 §13):
// every member reads them, only owners and administrators record and remove
// them; first-party names and catalog products are refused; the release
// line changes the verdicts of that organization's sensors only; without one
// a custom product gets only the SDK compatibility verdict; every change is
// audited.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
)

func TestSensorCustomProducts_Routes_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid, other := h.tenant(), h.tenant()
	owner, admin, member, viewer := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")
	outsider := h.member(other, "admin")
	const base = "/api/v1/sensors/custom-products"

	// A sensor of tenant A and one of tenant B, both reporting the same
	// custom product, built with sdk-go.
	sa, sb := h.sensor(tid), h.sensor(other)
	for _, id := range []string{sa, sb} {
		h.exec(`UPDATE sensors SET version = 'v1.1.0', sensor_product = 'acme-scanner', sdk_name = 'openctem-sdk-go', sdk_version = 'v0.34.0' WHERE id = $1`, id)
	}
	sensorView := func(u policyUser, id string) handler.SensorResponse {
		var s handler.SensorResponse
		mustJSON(t, h.expect(u, http.MethodGet, "/api/v1/sensors/"+id, "", http.StatusOK), &s)
		return s
	}
	// Without release information: no version verdict.
	if s := sensorView(admin, sa); s.ProductKnown || s.VersionStatus != "unknown" {
		t.Fatalf("before: known %v status %s", s.ProductKnown, s.VersionStatus)
	}

	// Only owners and administrators record and remove.
	for _, u := range []policyUser{member, viewer} {
		h.expect(u, http.MethodPut, base+"/acme-scanner", `{"latest_version":"v1.2.0"}`, http.StatusForbidden)
		h.expect(u, http.MethodDelete, base+"/acme-scanner", "", http.StatusForbidden)
	}
	var saved handler.CustomSensorProductResponse
	mustJSON(t, h.expect(admin, http.MethodPut, base+"/acme-scanner", `{"latest_version":"1.2.0","min_version":"v1.0.0"}`, http.StatusOK), &saved)
	if saved.Product != "acme-scanner" || saved.LatestVersion != "v1.2.0" || saved.MinVersion != "v1.0.0" || saved.UpdatedBy == nil || *saved.UpdatedBy != admin.id {
		t.Fatalf("saved = %+v", saved)
	}
	// Every member reads.
	for _, u := range []policyUser{owner, admin, member, viewer} {
		var list handler.CustomSensorProductListResponse
		mustJSON(t, h.expect(u, http.MethodGet, base, "", http.StatusOK), &list)
		if len(list.Items) != 1 || list.Items[0].Product != "acme-scanner" {
			t.Fatalf("%s list = %+v", u.role, list)
		}
	}

	// The organization's sensors now get the verdict.
	if s := sensorView(member, sa); !s.ProductKnown || s.VersionStatus != "update_available" || s.ProductLatestVersion != "v1.2.0" {
		t.Fatalf("after: %+v", s)
	}
	// Raising the minimum above the sensor makes it unsupported (degraded).
	h.expect(owner, http.MethodPut, base+"/acme-scanner", `{"latest_version":"v2.0.0","min_version":"v1.5.0"}`, http.StatusOK)
	if s := sensorView(member, sa); s.VersionStatus != "unsupported" {
		t.Fatalf("below min: %+v", s)
	}

	// SECURITY: another organization's release line never reaches tenant B:
	// its sensor of the same product name keeps no verdict, its list is
	// empty, and it cannot remove tenant A's row.
	if s := sensorView(outsider, sb); s.ProductKnown || s.VersionStatus != "unknown" {
		t.Fatalf("tenant B sees tenant A's line: %+v", s)
	}
	var otherList handler.CustomSensorProductListResponse
	mustJSON(t, h.expect(outsider, http.MethodGet, base, "", http.StatusOK), &otherList)
	if len(otherList.Items) != 0 {
		t.Fatalf("tenant B list = %+v", otherList)
	}
	h.expect(outsider, http.MethodDelete, base+"/acme-scanner", "", http.StatusNotFound)
	// ...and tenant A's sensor is still judged by A's line.
	if s := sensorView(admin, sa); !s.ProductKnown {
		t.Fatal("tenant B's delete reached tenant A")
	}

	// SECURITY: first-party names and catalog products are refused; values
	// that are not a token or a release are refused.
	for path, body := range map[string]string{
		"/openctemio-sensor":          `{"latest_version":"v99.0.0"}`,
		"/openctemio-anything":        `{}`,
		"/acme-scanner":               `{"latest_version":"latest"}`,
		"/acme-scanner?x=1":           `{"latest_version":"v1.0.0","min_version":"v2.0.0"}`,
		"/" + strings.Repeat("a", 65): `{}`,
		"/acme-other":                 `{"latest_version":"v1.0.0","image":"evil"}`,
		"/ACME%20scanner%3Brm%20-rf":  `{}`,
	} {
		h.expect(admin, http.MethodPut, base+path, body, http.StatusBadRequest)
	}

	// Removing it returns the sensor to compatibility verdicts only.
	h.expect(admin, http.MethodDelete, base+"/acme-scanner", "", http.StatusNoContent)
	h.expect(admin, http.MethodDelete, base+"/acme-scanner", "", http.StatusNotFound)
	if s := sensorView(admin, sa); s.ProductKnown || s.VersionStatus != "unknown" {
		t.Fatalf("after delete: %+v", s)
	}

	// Every change is audited in the organization's log.
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND resource_name = 'sensor product: acme-scanner'`, tid).Scan(&n); err != nil || n != 3 {
		t.Fatalf("audit rows = %d (%v), want 3", n, err)
	}
}

// The per-organization limit.
func TestSensorCustomProducts_Limit_DB(t *testing.T) {
	h := newActivityRouteHarness(t)
	tid := h.tenant()
	admin := h.member(tid, "admin")
	for i := 0; i < 50; i++ {
		h.exec(`INSERT INTO tenant_sensor_products (tenant_id, product, latest_version) VALUES ($1, $2, 'v1.0.0')`, tid, "p"+strings.Repeat("x", i%10)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	h.expect(admin, http.MethodPut, "/api/v1/sensors/custom-products/one-too-many", `{"latest_version":"v1.0.0"}`, http.StatusBadRequest)
	// Updating an existing one still works at the limit.
	h.expect(admin, http.MethodPut, "/api/v1/sensors/custom-products/paa", `{"latest_version":"v1.1.0"}`, http.StatusOK)
}
