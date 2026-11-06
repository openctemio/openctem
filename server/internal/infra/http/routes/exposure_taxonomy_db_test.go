package routes

// Exposure taxonomy on the exposure routes (docs/architecture/exposure-taxonomy.md):
// an in-scope member overrides an exposure's severity (reason required, the
// reported severity and the four-eyes peak kept), starts work on it, and
// lists by display category; another tenant's exposure is 404 even for the
// owner. The out-of-scope refusals are in TestDataScope_* (writes list).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestExposureTaxonomy_SeverityOverrideAndProgress(t *testing.T) {
	h := newDSHarness(t)
	a := "/api/v1/exposures/" + h.exposureA.String()

	// A reason is required.
	if status, body := h.do(h.memberA, false, http.MethodPatch, a+"/severity", map[string]any{"severity": "low"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("override without reason = %d, want 422 (%.200s)", status, body)
	}
	status, body := h.do(h.memberA, false, http.MethodPatch, a+"/severity", map[string]any{"severity": "low", "reason": "only reachable over VPN"})
	if status != http.StatusOK {
		t.Fatalf("in-scope override = %d (%.300s)", status, body)
	}
	var resp struct {
		Severity         string `json:"severity"`
		DisplayCategory  string `json:"display_category"`
		State            string `json:"state"`
		SeverityOverride *struct {
			ReportedSeverity string `json:"reported_severity"`
			Reason           string `json:"reason"`
			OverriddenBy     string `json:"overridden_by"`
		} `json:"severity_override"`
		Summary struct {
			Text string `json:"text"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Severity != "low" || resp.SeverityOverride == nil || resp.SeverityOverride.ReportedSeverity != "high" ||
		resp.SeverityOverride.OverriddenBy != h.memberA.String() || resp.DisplayCategory != "exposed_ports" || resp.Summary.Text == "" {
		t.Fatalf("override response: %.400s", body)
	}
	var sev, src, peak string
	var by sql.NullString
	if err := h.db.QueryRow(`SELECT severity, source_severity, peak_severity, severity_overridden_by FROM exposure_events WHERE id = $1`,
		h.exposureA.String()).Scan(&sev, &src, &peak, &by); err != nil {
		t.Fatal(err)
	}
	if sev != "low" || src != "high" || peak != "high" || by.String != h.memberA.String() {
		t.Fatalf("stored: severity=%s source=%s peak=%s by=%s", sev, src, peak, by.String)
	}

	// A re-sighting while the override stands keeps the analyst's severity
	// and records what the producer reported.
	repo := postgres.NewExposureRepository(&postgres.DB{DB: h.db})
	now := time.Now()
	ev := exposure.Reconstitute(shared.NewID(), h.tenant, &h.assetA, exposure.EventTypePortOpen, exposure.SeverityCritical,
		exposure.StateActive, "dsA exposure on A1", "", nil, h.exposureA.String(), "ds", now, now, nil, nil, "", now, now)
	if err := repo.Upsert(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	_ = h.db.QueryRow(`SELECT severity, source_severity, peak_severity FROM exposure_events WHERE id = $1`, h.exposureA.String()).Scan(&sev, &src, &peak)
	if sev != "low" || src != "critical" || peak != "critical" {
		t.Fatalf("re-sighting: severity=%s source=%s peak=%s", sev, src, peak)
	}

	// Removing the override restores the reported severity.
	if status, body := h.do(h.memberA, false, http.MethodPatch, a+"/severity", map[string]any{"severity": "", "reason": "scan is right"}); status != http.StatusOK ||
		!strings.Contains(body, `"severity":"critical"`) || strings.Contains(body, "severity_override") {
		t.Fatalf("restore = %d (%.300s)", status, body)
	}

	// Start progress: open, listed under in_progress, history from active.
	if status, body := h.do(h.memberA, false, http.MethodPost, a+"/start-progress", map[string]any{"reason": "on it"}); status != http.StatusOK ||
		!strings.Contains(body, `"state":"in_progress"`) {
		t.Fatalf("start-progress = %d (%.300s)", status, body)
	}
	var prev string
	_ = h.db.QueryRow(`SELECT previous_state FROM exposure_state_history WHERE exposure_event_id = $1 AND new_state = 'in_progress'`,
		h.exposureA.String()).Scan(&prev)
	if prev != "active" {
		t.Fatalf("history previous_state = %q", prev)
	}
	if status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/exposures?state=in_progress&category=exposed_ports", nil); status != http.StatusOK ||
		!strings.Contains(body, h.exposureA.String()) {
		t.Fatalf("list in_progress by category = %d (%.300s)", status, body)
	}
	if status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/exposures?category=dns", nil); status != http.StatusOK ||
		strings.Contains(body, h.exposureA.String()) {
		t.Fatalf("other category must not list it = %d (%.300s)", status, body)
	}
	if status, _ := h.do(h.memberA, false, http.MethodGet, "/api/v1/exposures?category=bogus", nil); status != http.StatusBadRequest {
		t.Fatalf("unknown category = %d, want 400", status)
	}
}

func TestExposureTaxonomy_OtherTenantIsNotFound(t *testing.T) {
	h := newDSHarness(t)
	other, asset, exp := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "tx-other-"+other.String())
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'tx-foreign', 'domain', 'public', 'high')`,
		asset.String(), other.String())
	h.exec(`INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, title, fingerprint, source, severity, state)
		VALUES ($1::uuid, $2, $3, 'port_open', 'tx foreign', $1::text, 'ds', 'high', 'active')`, exp.String(), other.String(), asset.String())
	p := "/api/v1/exposures/" + exp.String()
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPatch, p + "/severity", map[string]any{"severity": "info", "reason": "x"}},
		{http.MethodPost, p + "/start-progress", nil},
	} {
		if status, body := h.do(h.owner, true, c.method, c.path, c.body); status != http.StatusNotFound {
			t.Errorf("owner %s %s on another tenant = %d, want 404 (%.200s)", c.method, c.path, status, body)
		}
	}
	var sev, state string
	_ = h.db.QueryRow(`SELECT severity, state FROM exposure_events WHERE id = $1`, exp.String()).Scan(&sev, &state)
	if sev != "high" || state != "active" {
		t.Fatalf("another tenant's exposure changed: %s %s", sev, state)
	}
}
