package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/credential"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const revealTestSecret = "Reveal-Me-0nly-When-Audited!"

// revealStubRepo serves one exposure event; the embedded interface panics on
// anything else, which keeps the test honest about what reveal touches.
type revealStubRepo struct {
	exposure.Repository
	ev *exposure.ExposureEvent
}

func (r *revealStubRepo) GetByID(_ context.Context, id shared.ID) (*exposure.ExposureEvent, error) {
	if r.ev == nil || r.ev.ID() != id {
		return nil, exposure.NewExposureEventNotFoundError(id.String())
	}
	return r.ev, nil
}

func (r *revealStubRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*exposure.ExposureEvent, error) {
	if r.ev == nil || r.ev.ID() != id || r.ev.TenantID() != tenantID {
		return nil, exposure.NewExposureEventNotFoundError(id.String())
	}
	return r.ev, nil
}

type failingAuditRepo struct{ *fakeAuditRepo }

func (failingAuditRepo) Create(context.Context, *auditdom.AuditLog) error {
	return errors.New("audit store down")
}

func newRevealFixture(t *testing.T) (*CredentialImportHandler, *exposure.ExposureEvent) {
	t.Helper()
	c, err := crypto.NewCipherFromHex(strings.Repeat("1f", 32))
	if err != nil {
		t.Fatal(err)
	}
	p := credential.NewSecretProtector(c, []byte("k"))
	details := map[string]any{"credential_type": "password", credential.DetailSecretValue: revealTestSecret}
	if err := p.Seal(details); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ev := exposure.Reconstitute(shared.NewID(), shared.NewID(), nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateActive,
		"alice@corp.test", "", details, "fp", "data_breach", now, now, nil, nil, "", now, now)
	svc := integration.NewCredentialImportService(&revealStubRepo{ev: ev}, nil, logger.NewNop())
	svc.SetSecretProtector(p)
	return NewCredentialImportHandler(svc, nil, logger.NewNop()), ev
}

func doReveal(h *CredentialImportHandler, tenantID, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/"+id+"/reveal", nil)
	req.SetPathValue("id", id)
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenantID))
	rec := httptest.NewRecorder()
	h.RevealSecret(rec, req)
	return rec
}

func TestRevealSecret_ReturnsSecretAndWritesAudit(t *testing.T) {
	h, ev := newRevealFixture(t)
	repo := &fakeAuditRepo{}
	h.SetAuditService(auditapp.NewAuditService(repo, logger.NewNop()))

	rec := doReveal(h, ev.TenantID().String(), ev.ID().String())
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body RevealCredentialResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.SecretValue != revealTestSecret {
		t.Fatalf("body %s err %v", rec.Body.String(), err)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("a revealed secret must not be cacheable")
	}
	if len(repo.logs) != 1 {
		t.Fatalf("expected one audit event, got %d", len(repo.logs))
	}
	got := repo.logs[0]
	if got.Action() != auditdom.ActionCredentialRevealed || got.ResourceType() != auditdom.ResourceTypeCredential ||
		got.ResourceID() != ev.ID().String() {
		t.Fatalf("audit event = %s %s %s", got.Action(), got.ResourceType(), got.ResourceID())
	}
	if strings.Contains(got.Message(), revealTestSecret) {
		t.Fatal("the audit event must not contain the secret")
	}
}

func TestRevealSecret_FailsClosedWithoutAudit(t *testing.T) {
	h, ev := newRevealFixture(t)
	for name, configure := range map[string]func(){
		"no audit service": func() {},
		"audit write failed": func() {
			h.SetAuditService(auditapp.NewAuditService(failingAuditRepo{&fakeAuditRepo{}}, logger.NewNop()))
		},
	} {
		h.audit = nil
		configure()
		rec := doReveal(h, ev.TenantID().String(), ev.ID().String())
		if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), revealTestSecret) {
			t.Errorf("%s: status %d body %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestRevealSecret_OtherTenantGets404(t *testing.T) {
	h, ev := newRevealFixture(t)
	h.SetAuditService(auditapp.NewAuditService(&fakeAuditRepo{}, logger.NewNop()))
	rec := doReveal(h, shared.NewID().String(), ev.ID().String())
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), revealTestSecret) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestExposureResponse_NeverCarriesTheSecret(t *testing.T) {
	_, sealed := newRevealFixture(t)
	now := time.Now().UTC()
	legacy := exposure.Reconstitute(shared.NewID(), shared.NewID(), nil,
		exposure.EventTypeCredentialLeaked, exposure.SeverityHigh, exposure.StateActive,
		"bob@corp.test", "", map[string]any{"credential_type": "password", credential.DetailSecretValue: revealTestSecret},
		"fp2", "data_breach", now, now, nil, nil, "", now, now)
	for _, ev := range []*exposure.ExposureEvent{sealed, legacy} {
		raw, _ := json.Marshal(toExposureResponse(ev))
		s := string(raw)
		if strings.Contains(s, revealTestSecret) || strings.Contains(s, credential.DetailSecretCiphertext) {
			t.Fatalf("exposure response leaks the secret: %s", s)
		}
		if !strings.Contains(s, `"secret_masked":"********"`) {
			t.Fatalf("exposure response should carry the mask: %s", s)
		}
	}
}
