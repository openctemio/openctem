package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/command"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// A scan's scanner_config can hold tokens, passwords and Authorization
// headers. Callers that may read a scan but not edit it (no scans:write) see
// those values masked on every user-facing response; editors, owners and
// admins see them in clear.

const (
	redactTestPassword = "hunter2-real"
	redactTestBearer   = "Bearer eyJhbGciOiJIUzI1NiJ9.realpayload.sig"
)

func redactTestConfig() map[string]any {
	return map[string]any{
		"password": redactTestPassword,
		"headers": map[string]any{
			"Authorization": redactTestBearer,
			"X-Trace":       "plain-header",
		},
		"severity": "high",
		"rate":     50.0,
	}
}

// --- fakes ------------------------------------------------------------------

// redactScanRepo answers the calls GetScan, ListScans and UpdateScan make;
// any other call panics on the nil embedded interface.
type redactScanRepo struct {
	scan.Repository
	stored  *scan.Scan
	updated *scan.Scan
}

func (r *redactScanRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scan.Scan, error) {
	if r.stored == nil || r.stored.TenantID != tenantID || r.stored.ID != id {
		return nil, shared.ErrNotFound
	}
	return copyScan(r.stored), nil
}

func (r *redactScanRepo) List(_ context.Context, _ scan.Filter, page pagination.Pagination) (pagination.Result[*scan.Scan], error) {
	return pagination.NewResult([]*scan.Scan{copyScan(r.stored)}, 1, page), nil
}

func (r *redactScanRepo) Update(_ context.Context, s *scan.Scan) error {
	r.updated = s
	return nil
}

// copyScan returns the scan as a fresh load from the database would: the
// same row, with a config the caller cannot alias.
func copyScan(s *scan.Scan) *scan.Scan {
	c := *s
	raw, _ := json.Marshal(s.ScannerConfig)
	c.ScannerConfig = nil
	_ = json.Unmarshal(raw, &c.ScannerConfig)
	return &c
}

type redactCommandRepo struct {
	commanddom.Repository
	cmd *commanddom.Command
}

func (r *redactCommandRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*commanddom.Command, error) {
	if r.cmd.TenantID != tenantID || r.cmd.ID != id {
		return nil, shared.ErrNotFound
	}
	return r.cmd, nil
}

func (r *redactCommandRepo) List(_ context.Context, _ commanddom.Filter, page pagination.Pagination) (pagination.Result[*commanddom.Command], error) {
	return pagination.NewResult([]*commanddom.Command{r.cmd}, 1, page), nil
}

func newRedactScanFixture(t *testing.T) (*ScanHandler, *redactScanRepo, *scan.Scan) {
	t.Helper()
	tenant := shared.NewID()
	sc, err := scan.NewScan(tenant, "nightly", shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.SetSingleScanner("nuclei", redactTestConfig(), 1); err != nil {
		t.Fatal(err)
	}
	repo := &redactScanRepo{stored: sc}
	svc := scansvc.NewService(repo, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, logger.NewNop())
	return NewScanHandler(svc, nil, nil, validator.New(), logger.NewNop()), repo, sc
}

// --- caller contexts ----------------------------------------------------------

type caller struct {
	name   string
	admin  bool
	perms  []string
	reveal bool
}

var redactCallers = []caller{
	{name: "viewer (scans:read only)", perms: []string{permission.ScansRead.String(), permission.CommandsRead.String()}, reveal: false},
	{name: "no permissions resolved", perms: nil, reveal: false},
	{name: "member with scans:write", perms: []string{permission.ScansRead.String(), permission.ScansWrite.String(), permission.CommandsRead.String()}, reveal: true},
	{name: "owner/admin bypass", admin: true, reveal: true},
}

func withCaller(r *http.Request, tenant shared.ID, c caller, routeParams map[string]string) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.IsAdminKey, c.admin)
	if c.perms != nil {
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, c.perms)
	}
	if len(routeParams) > 0 {
		rc := chi.NewRouteContext()
		for k, v := range routeParams {
			rc.URLParams.Add(k, v)
		}
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rc)
	}
	return r.WithContext(ctx)
}

func assertRedaction(t *testing.T, body string, reveal bool) {
	t.Helper()
	for _, secret := range []string{redactTestPassword, "realpayload"} {
		if got := strings.Contains(body, secret); got != reveal {
			t.Errorf("secret %q visible=%v, want %v; body: %s", secret, got, reveal, body)
		}
	}
	if !reveal && !strings.Contains(body, scan.RedactedSecretValue) {
		t.Errorf("expected the mask in a redacted body: %s", body)
	}
	for _, plain := range []string{"plain-header", `"severity":"high"`} {
		if !strings.Contains(body, plain) {
			t.Errorf("non-secret value %q missing: %s", plain, body)
		}
	}
}

// --- scans ------------------------------------------------------------------

func TestScanConfigRedaction_GetScan(t *testing.T) {
	for _, c := range redactCallers {
		t.Run(c.name, func(t *testing.T) {
			h, _, sc := newRedactScanFixture(t)
			req := withCaller(httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+sc.ID.String(), nil),
				sc.TenantID, c, map[string]string{"id": sc.ID.String()})
			rec := httptest.NewRecorder()
			h.GetScan(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			body := rec.Body.String()
			assertRedaction(t, body, c.reveal)

			// The warnings name the flagged paths for every reader.
			var resp ScanDetailResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			got := map[string]bool{}
			for _, w := range resp.ScannerConfigWarnings {
				got[w.Path] = true
			}
			if !got["password"] || !got["headers.Authorization"] || len(got) != 2 {
				t.Fatalf("warnings = %v, want password and headers.Authorization", resp.ScannerConfigWarnings)
			}
		})
	}
}

func TestScanConfigRedaction_ListScans(t *testing.T) {
	for _, c := range redactCallers {
		t.Run(c.name, func(t *testing.T) {
			h, _, sc := newRedactScanFixture(t)
			req := withCaller(httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil), sc.TenantID, c, nil)
			rec := httptest.NewRecorder()
			h.ListScans(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			assertRedaction(t, rec.Body.String(), c.reveal)
		})
	}
}

func TestScanConfigRedaction_Export(t *testing.T) {
	for _, c := range redactCallers {
		t.Run(c.name, func(t *testing.T) {
			h, _, sc := newRedactScanFixture(t)
			req := withCaller(httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+sc.ID.String()+"/export", nil),
				sc.TenantID, c, map[string]string{"id": sc.ID.String()})
			rec := httptest.NewRecorder()
			h.ExportConfig(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			// Exports are indented; compact before matching.
			var buf bytes.Buffer
			if err := json.Compact(&buf, rec.Body.Bytes()); err != nil {
				t.Fatal(err)
			}
			assertRedaction(t, buf.String(), c.reveal)
		})
	}
}

// A config saved back with the mask in place keeps the stored secret; a new
// value replaces it. Writers are shown real values, so this is a guard
// against a client that echoes a masked config, not the normal path.
func TestScanConfigRedaction_UpdateWithMaskKeepsStoredSecret(t *testing.T) {
	h, repo, sc := newRedactScanFixture(t)
	member := redactCallers[2]

	cfg := scan.RedactConfigSecrets(redactTestConfig())
	cfg["severity"] = "critical"
	body, _ := json.Marshal(map[string]any{"scanner_name": "nuclei", "scanner_config": cfg})

	req := withCaller(httptest.NewRequest(http.MethodPut, "/api/v1/scans/"+sc.ID.String(), bytes.NewReader(body)),
		sc.TenantID, member, map[string]string{"id": sc.ID.String()})
	rec := httptest.NewRecorder()
	h.UpdateScan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if repo.updated == nil {
		t.Fatal("scan was not saved")
	}
	saved := repo.updated.ScannerConfig
	if saved["password"] != redactTestPassword {
		t.Fatalf("password saved as %v", saved["password"])
	}
	if saved["headers"].(map[string]any)["Authorization"] != redactTestBearer {
		t.Fatalf("Authorization saved as %v", saved["headers"])
	}
	if saved["severity"] != "critical" {
		t.Fatalf("non-secret edit lost: %v", saved["severity"])
	}

	// A new secret replaces the stored one.
	cfg = scan.RedactConfigSecrets(redactTestConfig())
	cfg["password"] = "rotated-pass"
	body, _ = json.Marshal(map[string]any{"scanner_name": "nuclei", "scanner_config": cfg})
	req = withCaller(httptest.NewRequest(http.MethodPut, "/api/v1/scans/"+sc.ID.String(), bytes.NewReader(body)),
		sc.TenantID, member, map[string]string{"id": sc.ID.String()})
	rec = httptest.NewRecorder()
	h.UpdateScan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got := repo.updated.ScannerConfig["password"]; got != "rotated-pass" {
		t.Fatalf("new password not saved: %v", got)
	}
}

// --- commands ---------------------------------------------------------------

func newRedactCommandFixture(t *testing.T) (*CommandHandler, *commanddom.Command) {
	t.Helper()
	tenant := shared.NewID()
	payload, _ := json.Marshal(map[string]any{
		"scan_id":        shared.NewID().String(),
		"scanner":        "nuclei",
		"scanner_config": redactTestConfig(),
		"config":         redactTestConfig(),
		"context":        map[string]any{"scanner_config": redactTestConfig()},
	})
	cmd, err := commanddom.NewCommand(tenant, commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatal(err)
	}
	svc := command.NewService(&redactCommandRepo{cmd: cmd}, logger.NewNop())
	return NewCommandHandler(svc, validator.New(), logger.NewNop()), cmd
}

func TestScanConfigRedaction_CommandGetAndList(t *testing.T) {
	for _, c := range redactCallers {
		t.Run(c.name, func(t *testing.T) {
			h, cmd := newRedactCommandFixture(t)

			req := withCaller(httptest.NewRequest(http.MethodGet, "/api/v1/commands/"+cmd.ID.String(), nil),
				cmd.TenantID, c, map[string]string{"id": cmd.ID.String()})
			rec := httptest.NewRecorder()
			h.Get(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("get status %d: %s", rec.Code, rec.Body)
			}
			assertRedaction(t, rec.Body.String(), c.reveal)

			req = withCaller(httptest.NewRequest(http.MethodGet, "/api/v1/commands", nil), cmd.TenantID, c, nil)
			rec = httptest.NewRecorder()
			h.List(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("list status %d: %s", rec.Code, rec.Body)
			}
			assertRedaction(t, rec.Body.String(), c.reveal)
		})
	}
}

// The stored command, which is what a sensor claims, is never modified by a
// redacted read.
func TestScanConfigRedaction_CommandStoredPayloadUntouched(t *testing.T) {
	h, cmd := newRedactCommandFixture(t)
	before := string(cmd.Payload)
	req := withCaller(httptest.NewRequest(http.MethodGet, "/api/v1/commands/"+cmd.ID.String(), nil),
		cmd.TenantID, redactCallers[0], map[string]string{"id": cmd.ID.String()})
	h.Get(httptest.NewRecorder(), req)
	if string(cmd.Payload) != before || !strings.Contains(before, redactTestPassword) {
		t.Fatal("redaction changed the stored command payload")
	}
}
