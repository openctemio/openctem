package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/command"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// POST /api/v1/commands with type "scan" (RFC-040 Q5 (c)): owner/admin only,
// and the targets get the scan trigger's checks. Before the fix a member
// could send any target to any sensor of the tenant.

type createdCommandRepo struct {
	commanddom.Repository
	created []*commanddom.Command
}

func (r *createdCommandRepo) Create(_ context.Context, c *commanddom.Command) error {
	r.created = append(r.created, c)
	return nil
}

type excludeValues map[string]bool

func (e excludeValues) ExcludedTargets(_ context.Context, _ string, cs []scope.ExclusionCandidate) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	for _, c := range cs {
		for _, v := range c.Values {
			if e[v] {
				out[c.ID] = true
			}
		}
	}
	return out, nil
}

type scanCommandFixture struct {
	h        *CommandHandler
	repo     *createdCommandRepo
	audit    *fakeAuditRepo
	tenantID string
	userID   string
}

func newScanCommandFixture() *scanCommandFixture {
	f := &scanCommandFixture{
		repo:     &createdCommandRepo{},
		audit:    &fakeAuditRepo{},
		tenantID: shared.NewID().String(),
		userID:   shared.NewID().String(),
	}
	f.h = NewCommandHandler(command.NewService(f.repo, logger.NewNop()), validator.New(), logger.NewNop())
	f.h.SetAuditService(auditapp.NewAuditService(f.audit, logger.NewNop()))
	f.h.SetScanCommandGate(scanapp.NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		logger.NewNop(), scanapp.WithScopeExclusionFilter(excludeValues{"payroll.example.com": true})))
	return f
}

func (f *scanCommandFixture) post(t *testing.T, admin bool, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := auditedRequest(http.MethodPost, "/api/v1/commands", []byte(body), f.tenantID, f.userID, "")
	req = req.WithContext(context.WithValue(req.Context(), middleware.IsAdminKey, admin))
	rec := httptest.NewRecorder()
	f.h.Create(rec, req)
	return rec
}

func (f *scanCommandFixture) requireResult(t *testing.T, result auditdom.Result) {
	t.Helper()
	for _, l := range f.audit.logs {
		if l.Action() == auditdom.ActionCommandCreated && l.Result() == result {
			if l.ActorID() == nil || l.ActorID().String() != f.userID {
				t.Fatalf("audit entry actor %v, want %s", l.ActorID(), f.userID)
			}
			return
		}
	}
	t.Fatalf("no %s audit entry for command.created (got %d entries)", result, len(f.audit.logs))
}

func TestCommandCreate_ScanByMemberForbidden(t *testing.T) {
	f := newScanCommandFixture()
	rec := f.post(t, false, `{"type":"scan","payload":{"scanner":"nuclei","target":"10.0.0.5"}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member sending a scan command: status %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	if len(f.repo.created) != 0 {
		t.Fatal("member's scan command was stored")
	}
	f.requireResult(t, auditdom.ResultDenied)
}

func TestCommandCreate_MemberKeepsNonScanCommands(t *testing.T) {
	f := newScanCommandFixture()
	rec := f.post(t, false, `{"type":"health_check"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("member health_check: status %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestCommandCreate_ScanByAdminOutOfScopeRefused(t *testing.T) {
	for name, body := range map[string]string{
		"excluded target":         `{"type":"scan","payload":{"scanner":"nuclei","targets":["app.example.com","payroll.example.com"]}}`,
		"private target, no zone": `{"type":"scan","payload":{"scanner":"nmap","target":"10.0.0.5"}}`,
		"cloud metadata":          `{"type":"scan","payload":{"scanner":"nuclei","target":"http://169.254.169.254/"}}`,
		"no target":               `{"type":"scan","payload":{"scanner":"nuclei"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newScanCommandFixture()
			rec := f.post(t, true, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			if len(f.repo.created) != 0 {
				t.Fatal("refused scan command was stored")
			}
			f.requireResult(t, auditdom.ResultDenied)
		})
	}
}

func TestCommandCreate_ScanByAdminInScopeAccepted(t *testing.T) {
	f := newScanCommandFixture()
	rec := f.post(t, true, `{"type":"scan","payload":{"scanner":"nuclei","target":"app.example.com","targets":["api.example.com"]}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	if len(f.repo.created) != 1 {
		t.Fatalf("stored %d commands, want 1", len(f.repo.created))
	}
	var p struct {
		Target  *string  `json:"target"`
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(f.repo.created[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Target != nil || strings.Join(p.Targets, ",") != "app.example.com,api.example.com" {
		t.Fatalf("payload targets not the checked list: %s", f.repo.created[0].Payload)
	}
	// The claim re-checks the targets with what was checked here: the
	// scanner's tier ceiling and the caller's act scope.
	if g := f.repo.created[0].DispatchGate; g == nil || *g != (commanddom.DispatchGate{Tier: 1, ActScope: true, Actor: f.userID}) {
		t.Fatalf("dispatch gate %+v", g)
	}
	f.requireResult(t, auditdom.ResultSuccess)
	for _, l := range f.audit.logs {
		if l.Result() == auditdom.ResultSuccess {
			if _, ok := l.Metadata()["targets"]; !ok {
				t.Fatalf("audit entry does not record the targets: %v", l.Metadata())
			}
		}
	}
}

func TestCommandCreate_ScanFailsClosedWithoutGate(t *testing.T) {
	f := newScanCommandFixture()
	f.h.scanGate = nil
	rec := f.post(t, true, `{"type":"scan","payload":{"scanner":"nuclei","target":"app.example.com"}}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
	if len(f.repo.created) != 0 {
		t.Fatal("scan command stored without the target checks")
	}
}
