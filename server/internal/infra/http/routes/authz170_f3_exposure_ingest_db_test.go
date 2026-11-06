package routes

// Research 170 (assets authz audit), fork 3. POST /api/v1/exposures/ingest is
// classified "gap" in route_scope_classification_test.go ("the fingerprint
// upsert can overwrite an out-of-scope or asset-less exposure"). The
// fingerprint hashes tenant + asset id, every asset id goes through
// FilterAssetRefs (tenant + caller scope) and an asset-less item needs an
// unrestricted caller, so a scoped member can no longer reach another
// asset's row. This test pins that (it PASSES on develop b9f14be96).

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAuthz170F3_ExposureIngest_ScopedMemberCannotTouchOutOfScope(t *testing.T) {
	h := newDSHarness(t)
	count := func() int {
		var n int
		if err := h.db.QueryRow(`SELECT count(*) FROM exposure_events WHERE tenant_id = $1`, h.tenant.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()

	// Seed an out-of-scope exposure whose fingerprint is the real one, so a
	// colliding upsert would hit it.
	fpB := exposure.Fingerprint(h.tenant.String(), "port_open", "f3-target", "f3", h.assetB.String(), nil)
	idB := shared.NewID()
	h.exec(`INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, title, fingerprint, source, severity, state)
		VALUES ($1, $2, $3, 'port_open', 'f3-target', $4, 'f3', 'low', 'active')`, idB.String(), h.tenant.String(), h.assetB.String(), fpB)
	before++

	item := func(assetID string) map[string]any {
		m := map[string]any{"event_type": "port_open", "severity": "critical", "title": "f3-target", "source": "f3"}
		if assetID != "" {
			m["asset_id"] = assetID
		}
		return m
	}
	foreign := shared.NewID().String() // unknown / another tenant's id answers alike
	status, body := h.do(h.memberA, false, http.MethodPost, "/api/v1/exposures/ingest",
		map[string]any{"exposures": []any{item(h.assetB.String()), item(""), item(foreign), item(h.assetA.String())}})
	if status >= 300 {
		t.Fatalf("ingest = %d (body %.300s)", status, body)
	}
	if n := count(); n != before+1 {
		t.Errorf("rows written = %d, want exactly 1 (the in-scope item only)", n-before)
	}
	var sev string
	_ = h.db.QueryRow(`SELECT severity FROM exposure_events WHERE id = $1`, idB.String()).Scan(&sev)
	if sev != "low" {
		t.Errorf("out-of-scope exposure overwritten through ingest: severity=%s", sev)
	}
	if !strings.Contains(body, "asset") {
		t.Logf("body: %.300s", body)
	}
}
