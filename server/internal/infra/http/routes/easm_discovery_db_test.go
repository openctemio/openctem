package routes

// /attack-surface/discovery: the coverage work counts and actions are the
// caller's tenant's only (another tenant's ledger rows, runs and attribution
// writes never count, are never made due and never canceled), and a member
// whose data scope is restricted is refused (403) instead of being shown
// organization totals.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type discOnSwitch struct{}

func (discOnSwitch) CoverageEnabled(context.Context, shared.ID) (bool, error) { return true, nil }

type discCanceller struct {
	mu   sync.Mutex
	runs []string
}

func (c *discCanceller) CancelRun(_ context.Context, tenantID, runID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runs = append(c.runs, tenantID+"/"+runID)
	return nil
}

type discSeed struct {
	other                                  shared.ID
	ownActiveRun, otherActiveRun, ownScanB string
}

// seedDiscovery: resolve.dns pairs for A and B (covered, due in a day) and
// one paused pair, a coverage scan with a finished run (whose window holds
// one automatic attribution write and one person's decision) and an active
// run, and the same in another tenant.
func (h *dsHarness) seedDiscovery() discSeed {
	h.t.Helper()
	tn := h.tenant.String()
	var s discSeed
	s.other = shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, s.other.String(), "disc-other-"+s.other.String())
	h.t.Cleanup(func() {
		_, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, s.other.String())
		_, _ = h.db.Exec(`DELETE FROM controller_leases WHERE name LIKE $1`, "easm_discovery_run:"+tn+"%")
	})
	otherAsset := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'disc-other.example', 'domain', 'public', 'low')`,
		otherAsset.String(), s.other.String())
	pair := `INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, reason, next_due_at, last_attempt_at)
		VALUES ($1, $2, $3, '', $4, $5, now() + interval '1 day', now() - interval '1 hour')`
	h.exec(pair, tn, h.assetA.String(), "resolve.dns", "covered", "")
	h.exec(pair, tn, h.assetB.String(), "resolve.dns", "covered", "")
	h.exec(pair, tn, h.assetA.String(), "lookup.rdap", "paused", "tool_missing")
	h.exec(pair, s.other.String(), otherAsset.String(), "resolve.dns", "covered", "")

	scanIns := `INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets, managed_by, managed_key)
		VALUES ($1, $2, $3, 'single', 'dnsx', ARRAY['disc.example'], 'coverage', 'resolve.dns')`
	ownScan, otherScan := shared.NewID(), shared.NewID()
	h.exec(scanIns, ownScan.String(), tn, "coverage resolve.dns "+ownScan.String())
	h.exec(scanIns, otherScan.String(), s.other.String(), "coverage resolve.dns "+otherScan.String())
	runIns := `INSERT INTO scan_runs (id, tenant_id, scan_id, trigger_type, status, kind, created_at, started_at, completed_at)
		VALUES ($1, $2, $3, 'system', $4, 'system', $5, $5, $6)`
	start := time.Now().Add(-2 * time.Hour).UTC()
	h.exec(runIns, shared.NewID().String(), tn, ownScan.String(), "completed", start, start.Add(10*time.Minute))
	s.ownActiveRun, s.otherActiveRun = shared.NewID().String(), shared.NewID().String()
	// The active runs are newer (their window is open): created now.
	h.exec(runIns, s.ownActiveRun, tn, ownScan.String(), "running", time.Now().UTC(), nil)
	h.exec(runIns, s.otherActiveRun, s.other.String(), otherScan.String(), "running", time.Now().UTC(), nil)
	// A person's scan run with the same status is never touched.
	people := shared.NewID()
	h.exec(`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets) VALUES ($1, $2, $3, 'single', 'dnsx', ARRAY['disc.example'])`,
		people.String(), tn, "people "+people.String())
	s.ownScanB = shared.NewID().String()
	h.exec(runIns, s.ownScanB, tn, people.String(), "running", time.Now().UTC(), nil)

	// Attribution: an automatic write on A and on the other tenant's asset
	// inside the open window; a person's decision on B.
	h.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, updated_at) VALUES ($1, $2, 'discovered', 60, now())`,
		h.assetA.String(), tn)
	h.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, decided_at, updated_at) VALUES ($1, $2, 'confirmed', 0, now(), now())`,
		h.assetB.String(), tn)
	h.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, updated_at) VALUES ($1, $2, 'discovered', 60, now())`,
		otherAsset.String(), s.other.String())
	return s
}

func TestEASMDiscovery_TenantAndScope_DB(t *testing.T) {
	h := newDSHarness(t)
	s := h.seedDiscovery()
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewAssetCoverageRepository(db)
	canceller := &discCanceller{}
	disc := coverageapp.NewDiscovery(repo, repo, discOnSwitch{}, canceller, postgres.NewDiscoveryRunLimiter(db),
		coverageapp.DiscoveryConfig{LoopEnabled: true, Interval: time.Minute, DailyBudget: 5000}, logger.NewNop())
	router := infrahttp.NewChiRouter()
	registerEASMDiscoveryRoutes(router, handler.NewEASMDiscoveryHandler(disc, h.enforcer, nil, logger.NewNop()),
		Middleware(h.dsAuth), nil, passthrough)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	h.srv = srv
	const base = "/api/v1/attack-surface/discovery"

	// Restricted members (a scope row, or none) are refused; the full-data
	// member and the owner read the discovery stages.
	for _, u := range []shared.ID{h.memberA, h.memberStrict} {
		if st, body := h.do(u, false, http.MethodGet, base, nil); st != http.StatusForbidden || !strings.Contains(body, "DISCOVERY_FULL_DATA_REQUIRED") {
			t.Errorf("restricted member read = %d %s", st, body)
		}
		if st, _ := h.do(u, false, http.MethodGet, base+"/export", nil); st != http.StatusForbidden {
			t.Errorf("restricted member export = %d", st)
		}
	}
	if st, body := h.do(h.memberFull, false, http.MethodGet, base, nil); st != http.StatusOK {
		t.Errorf("full-data member read = %d %s", st, body)
	}

	st, body := h.do(h.owner, true, http.MethodGet, base, nil)
	if st != http.StatusOK {
		t.Fatalf("owner read = %d %s", st, body)
	}
	var o handler.DiscoveryOverviewResponse
	if err := json.Unmarshal([]byte(body), &o); err != nil {
		t.Fatal(err)
	}
	var validation *handler.DiscoveryStageResponse
	for i := range o.Stages {
		if o.Stages[i].Stage == "validation_scoping" {
			validation = &o.Stages[i]
		}
	}
	if validation == nil || validation.AutoValidatedAssets == nil {
		t.Fatalf("no validation stage: %s", body)
	}
	// One automatic attribution write of this tenant in the window: the
	// person's decision and the other tenant's write do not count.
	if *validation.AutoValidatedAssets != 1 || o.AutoValidation.Assets != 1 {
		t.Errorf("auto-validated = %d", *validation.AutoValidatedAssets)
	}
	if validation.Status != "running" || validation.ProgressUnit != "tasks" {
		t.Errorf("validation stage = %+v", validation)
	}
	for _, c := range validation.Capabilities {
		switch c.Capability {
		case "resolve.dns":
			if c.Pairs != 2 || c.Covered != 2 || c.LastRun == nil || c.LastRun.ID != s.ownActiveRun {
				t.Errorf("resolve.dns = %+v", c)
			}
		case "lookup.rdap":
			if c.Paused != 1 || c.PausedReason != "tool_missing" {
				t.Errorf("lookup.rdap = %+v", c)
			}
		}
	}

	// A restricted member cannot run or abort (scope refusal before the
	// service; the permission gate comes first for a member without it).
	if st, _ := h.do(h.memberA, false, http.MethodPost, base+"/cancel", nil); st != http.StatusForbidden {
		t.Errorf("restricted abort = %d", st)
	}

	// Run makes only this tenant's covered pairs of the stage due.
	st, body = h.do(h.owner, true, http.MethodPost, base+"/stages/validation_scoping/run", nil)
	if st != http.StatusAccepted || !strings.Contains(body, `"pairs_made_due":2`) {
		t.Fatalf("run = %d %s", st, body)
	}
	var dueOwn, dueOther, paused int
	_ = h.db.QueryRow(`SELECT count(*) FROM asset_coverage WHERE tenant_id = $1 AND capability = 'resolve.dns' AND next_due_at <= now()`, h.tenant.String()).Scan(&dueOwn)
	_ = h.db.QueryRow(`SELECT count(*) FROM asset_coverage WHERE tenant_id = $1 AND next_due_at <= now()`, s.other.String()).Scan(&dueOther)
	_ = h.db.QueryRow(`SELECT count(*) FROM asset_coverage WHERE tenant_id = $1 AND capability = 'lookup.rdap' AND state = 'paused' AND next_due_at > now()`, h.tenant.String()).Scan(&paused)
	if dueOwn != 2 || dueOther != 0 || paused != 1 {
		t.Errorf("due own=%d other=%d paused kept=%d", dueOwn, dueOther, paused)
	}
	// Once a minute per stage: 429 with Retry-After.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+base+"/stages/validation_scoping/run", nil)
	req.Header.Set("X-Test-User", h.owner.String())
	req.Header.Set("X-Test-Admin", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("second run = %d retry-after %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if st, body := h.do(h.owner, true, http.MethodGet, base, nil); st != http.StatusOK || !strings.Contains(body, `"run_available_at"`) {
		t.Errorf("run availability not shown: %d %s", st, body)
	}

	// Abort all cancels this tenant's coverage run only: never the other
	// tenant's, never a person's scan run.
	if st, body := h.do(h.owner, true, http.MethodPost, base+"/cancel", nil); st != http.StatusOK || !strings.Contains(body, `"canceled":1`) {
		t.Fatalf("abort = %d %s", st, body)
	}
	if len(canceller.runs) != 1 || canceller.runs[0] != h.tenant.String()+"/"+s.ownActiveRun {
		t.Errorf("canceled = %v (other %s, person %s)", canceller.runs, s.otherActiveRun, s.ownScanB)
	}

	// The export carries this tenant's rows only.
	if st, body := h.do(h.owner, true, http.MethodGet, base+"/export", nil); st != http.StatusOK ||
		!strings.Contains(body, "validation_scoping,running,,resolve.dns,2,2") {
		t.Errorf("export = %d %s", st, body)
	}
}
