package routes

// Remediation campaign saves (research 156 B4, B5, B15, B19): a full save is
// optimistic (a stale version is refused with 409), counter refreshes never
// touch status, a GET never writes, completing a campaign of 1,000+ findings
// works, and the reconciler rotates through campaigns.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/exposure"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type campaignSaveEnv struct {
	h    *dsHarness
	repo *postgres.RemediationCampaignRepository
	svc  *exposure.RemediationCampaignService
	srv  *httptest.Server
}

func newCampaignSaveEnv(t *testing.T) *campaignSaveEnv {
	t.Helper()
	h := newDSHarness(t)
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	repo := postgres.NewRemediationCampaignRepository(db)
	svc := exposure.NewRemediationCampaignService(repo, log)
	svc.SetFindingCounter(postgres.NewFindingRepository(db))
	svc.SetFindingLister(postgres.NewFindingRepository(db))
	router := infrahttp.NewChiRouter()
	registerRemediationCampaignRoutes(router, handler.NewRemediationCampaignHandler(svc, log), Middleware(h.dsAuth), nil, passthrough)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	return &campaignSaveEnv{h: h, repo: repo, svc: svc, srv: srv}
}

// campaign inserts an active campaign over the harness's two high findings.
func (e *campaignSaveEnv) campaign(status string) shared.ID {
	id := shared.NewID()
	e.h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter)
		VALUES ($1, $2, 'rc-save', $3, '{"severities": ["high"]}')`, id.String(), e.h.tenant.String(), status)
	return id
}

func (e *campaignSaveEnv) call(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r, _ := http.NewRequestWithContext(context.Background(), method, e.srv.URL+path, rd)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Test-User", e.h.owner.String())
	r.Header.Set("X-Test-Admin", "1")
	r.Header.Set("X-Test-Perms", strings.Join([]string{permission.RemediationRead.String(), permission.RemediationWrite.String()}, ","))
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

type campaignRow struct {
	status, name, priority string
	version, findings      int
	updatedAt              time.Time
}

func (e *campaignSaveEnv) row(t *testing.T, id shared.ID) campaignRow {
	t.Helper()
	var r campaignRow
	if err := e.h.db.QueryRowContext(context.Background(),
		`SELECT status, name, priority, version, finding_count, updated_at FROM remediation_campaigns WHERE tenant_id = $1 AND id = $2`,
		e.h.tenant.String(), id.String()).Scan(&r.status, &r.name, &r.priority, &r.version, &r.findings, &r.updatedAt); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRemediationCampaign_StaleSaveIsRefused_DB(t *testing.T) {
	e := newCampaignSaveEnv(t)
	id := e.campaign("active")
	path := "/api/v1/remediation/campaigns/" + id.String()

	// Creating through the API stores version 1.
	if code, created := e.call(t, http.MethodPost, "/api/v1/remediation/campaigns/", map[string]any{"name": "rc-created", "priority": "high"}); code != http.StatusCreated || created["version"] != float64(1) {
		t.Fatalf("create = %d %v, want 201 at version 1", code, created)
	}

	code, got := e.call(t, http.MethodPatch, path, map[string]any{"name": "first", "version": 1})
	if code != http.StatusOK {
		t.Fatalf("PATCH at the current version = %d %v", code, got)
	}
	if v, _ := got["version"].(float64); v != 2 {
		t.Fatalf("version after a save = %v, want 2", got["version"])
	}
	// A second tab still holds version 1.
	if code, _ := e.call(t, http.MethodPatch, path, map[string]any{"name": "second", "version": 1}); code != http.StatusConflict {
		t.Fatalf("PATCH on a stale version = %d, want 409", code)
	}
	if code, _ := e.call(t, http.MethodPatch, path+"/status", map[string]any{"status": "paused", "version": 1}); code != http.StatusConflict {
		t.Fatalf("status change on a stale version = %d, want 409", code)
	}
	if r := e.row(t, id); r.name != "first" || r.status != "active" || r.version != 2 {
		t.Fatalf("stale saves changed the campaign: %+v", r)
	}

	// Priority is the API's enum; the old web value is refused, not stored.
	if code, _ := e.call(t, http.MethodPatch, path, map[string]any{"priority": "urgent"}); code != http.StatusBadRequest {
		t.Fatalf("priority urgent = %d, want 400", code)
	}
	if code, _ := e.call(t, http.MethodPatch, path, map[string]any{"name": "  "}); code != http.StatusBadRequest {
		t.Fatalf("empty name = %d, want 400", code)
	}
	if _, err := e.h.db.ExecContext(context.Background(), `UPDATE remediation_campaigns SET priority = 'urgent' WHERE id = $1`, id.String()); err == nil {
		t.Fatal("the database accepted priority 'urgent'")
	}
}

func TestRemediationCampaign_ReconcileNeverUndoesCancelOrPause_DB(t *testing.T) {
	e := newCampaignSaveEnv(t)
	ctx := context.Background()
	// Both findings closed: the campaign is eligible to auto-complete.
	e.h.exec(`UPDATE findings SET status = 'resolved', resolved_at = now() WHERE tenant_id = $1`, e.h.tenant.String())

	// The reconciler read the campaign, then a person canceled it.
	canceled := e.campaign("active")
	stale, err := e.repo.GetByID(ctx, e.h.tenant, canceled)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateCampaignStatus(ctx, e.h.tenant.String(), canceled.String(), "canceled", audit.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	stale.UpdateProgress(2, 2)
	if _, cerr := stale.TryAutoComplete(); cerr != nil {
		t.Fatal(cerr)
	}
	if err := e.repo.Update(ctx, stale); !errors.Is(err, remediation.ErrCampaignVersionConflict) {
		t.Fatalf("stale reconciler save = %v, want a version conflict", err)
	}
	if r := e.row(t, canceled); r.status != "canceled" {
		t.Fatalf("a stale save reverted Cancel: status %s", r.status)
	}

	// A paused campaign gets fresh counters from the reconciler, never a
	// status change.
	paused := e.campaign("paused")
	if _, err := e.svc.ReconcileProgress(ctx); err != nil {
		t.Fatal(err)
	}
	if r := e.row(t, paused); r.status != "paused" || r.findings != 2 || r.version != 1 {
		t.Fatalf("paused campaign after reconcile = %+v, want paused with 2 findings at version 1", r)
	}
	if r := e.row(t, canceled); r.status != "canceled" {
		t.Fatalf("reconcile changed a canceled campaign: %s", r.status)
	}
}

func TestRemediationCampaign_GetNeverWrites_DB(t *testing.T) {
	e := newCampaignSaveEnv(t)
	id := e.campaign("active")
	before := e.row(t, id)
	code, got := e.call(t, http.MethodGet, "/api/v1/remediation/campaigns/"+id.String(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET = %d", code)
	}
	// The response carries the live counts...
	if n, _ := got["finding_count"].(float64); n != 2 {
		t.Fatalf("GET finding_count = %v, want the live 2", got["finding_count"])
	}
	// ...but nothing is persisted.
	after := e.row(t, id)
	if after.findings != before.findings || after.version != before.version || !after.updatedAt.Equal(before.updatedAt) {
		t.Fatalf("GET wrote the campaign: before %+v after %+v", before, after)
	}
}

func TestRemediationCampaign_CompletesWithManyFindings_DB(t *testing.T) {
	e := newCampaignSaveEnv(t)
	ctx := context.Background()
	// 1,200 resolved low findings: completing used to write the counts into
	// numeric(5,2) risk columns and fail.
	e.h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, resolved_at)
		SELECT gen_random_uuid(), $1, $2, 'sast', 'rc-many', 'many', 'low', 'rc-many-' || g, 'resolved', now()
		FROM generate_series(1, 1200) g`, e.h.tenant.String(), e.h.assetA.String())
	id := shared.NewID()
	e.h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, finding_filter)
		VALUES ($1, $2, 'rc-many', 'active', '{"severities": ["low"]}')`, id.String(), e.h.tenant.String())

	c, err := e.svc.UpdateCampaignStatus(ctx, e.h.tenant.String(), id.String(), "completed", audit.AuditContext{})
	if err != nil {
		t.Fatalf("completing a 1,200-finding campaign: %v", err)
	}
	if c.FindingCount() != 1200 || c.RiskReduction() != nil {
		t.Fatalf("completed campaign = %d findings, risk %v; want 1200 and no count stored as risk", c.FindingCount(), c.RiskReduction())
	}
	if r := e.row(t, id); r.status != "completed" {
		t.Fatalf("status = %s", r.status)
	}
}

func TestRemediationCampaign_ReconcilerRotates_DB(t *testing.T) {
	e := newCampaignSaveEnv(t)
	ctx := context.Background()
	visited := e.campaign("active")
	fresh := e.campaign("active")
	// The visited campaign is the least recently UPDATED one: ordering by
	// updated_at (and not persisting unchanged rows) picked it every run.
	e.h.exec(`UPDATE remediation_campaigns SET updated_at = now() - interval '30 days' WHERE id = $1`, visited.String())
	c, err := e.repo.GetByID(ctx, e.h.tenant, visited)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.repo.UpdateCounts(ctx, c); err != nil { // unchanged counts still stamp it
		t.Fatal(err)
	}
	list, err := e.repo.ListNonTerminal(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	pos := map[shared.ID]int{}
	for i, x := range list {
		pos[x.ID()] = i
	}
	pv, okV := pos[visited]
	pf, okF := pos[fresh]
	if !okV || !okF || pf > pv {
		t.Fatalf("never-reconciled campaign at %d (%v), just-reconciled at %d (%v): want the fresh one first", pf, okF, pv, okV)
	}
}
