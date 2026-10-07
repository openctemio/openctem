package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeSeeder struct {
	tenant    shared.ID
	in        easmapp.CreateSeedInput
	err       error
	approvals int  // the created entry's approval count (0: in effect)
	turnedOn  bool // Update reports discovery switched on
}

func (f *fakeSeeder) List(_ context.Context, tid shared.ID) ([]easmapp.SeedView, error) {
	f.tenant = tid
	return []easmapp.SeedView{}, f.err
}

func (f *fakeSeeder) Create(_ context.Context, tid shared.ID, in easmapp.CreateSeedInput) (*scopedom.Target, error) {
	f.tenant, f.in = tid, in
	if f.err != nil {
		return nil, f.err
	}
	return scopedom.NewEntry(tid, scopedom.TargetTypeDomain, "*."+in.Value, "", in.Actor.UserID,
		scopedom.EntryOptions{Reason: "seed", MaxTier: scopedom.TierActive, ApprovalsRequired: f.approvals, Now: time.Now()})
}

func (f *fakeSeeder) Update(_ context.Context, tid, _ shared.ID, _ *string, _ *bool) (*easmapp.SeedView, bool, error) {
	f.tenant = tid
	if f.err != nil {
		return nil, false, f.err
	}
	return &easmapp.SeedView{ID: shared.NewID().String(), Kind: "root_domain", Value: "acme.com", DiscoveryEnabled: true}, f.turnedOn, nil
}

func (f *fakeSeeder) Delete(_ context.Context, tid, id shared.ID) (*easmseed.Seed, error) {
	f.tenant = tid
	if f.err != nil {
		return nil, f.err
	}
	return &easmseed.Seed{ID: id, Kind: easmseed.KindRootDomain, Value: "acme.com"}, nil
}

type seedNotices struct{ titles []string }

func (n *seedNotices) NotifyAdmins(_ context.Context, _ shared.ID, title, _ string) {
	n.titles = append(n.titles, title)
}

func seedReq(method, target, body string, tenant shared.ID, user string, perms ...string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.UserIDKey, user)
	if len(perms) > 0 {
		ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
	}
	return req.WithContext(ctx)
}

func TestEASMSeedHandler_CreateAuditsWithTheTokenTenant(t *testing.T) {
	tenant, user := shared.NewID(), shared.NewID().String()
	svc := &fakeSeeder{}
	audit := &fakeAuditor{}
	h := NewEASMSeedHandler(svc, audit, logger.NewNop())

	rec := httptest.NewRecorder()
	h.Create(rec, seedReq(http.MethodPost, "/api/v1/easm/seeds",
		`{"kind":"root_domain","value":"acme.com","attested":true,"tenant_id":"`+shared.NewID().String()+`"}`,
		tenant, user, permission.ScopeApprove.String()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	// The tenant comes from the token context; a tenant_id in the body is
	// ignored. The actor carries the approve permission from the token.
	if svc.tenant != tenant || svc.in.Actor.UserID != user || !svc.in.Actor.CanApprove || !svc.in.Attested {
		t.Fatalf("tenant %v input %+v", svc.tenant, svc.in)
	}
	var body ScopeTargetResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Pattern != "*.acme.com" || body.Status != "active" {
		t.Fatalf("body %s (%v)", rec.Body, err)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d", len(audit.events))
	}
}

// A member's token reaches the service without the approve permission.
func TestEASMSeedHandler_MemberActorCannotApprove(t *testing.T) {
	svc := &fakeSeeder{}
	rec := httptest.NewRecorder()
	NewEASMSeedHandler(svc, nil, logger.NewNop()).Create(rec, seedReq(http.MethodPost, "/",
		`{"kind":"root_domain","value":"acme.com","attested":true}`, shared.NewID(), "member", permission.ScopeWrite.String()))
	if svc.in.Actor.CanApprove {
		t.Fatal("a member was treated as an approver")
	}
}

func TestEASMSeedHandler_PendingEntryIs202(t *testing.T) {
	sw := &recordingSweeper{}
	h := NewEASMSeedHandler(&fakeSeeder{approvals: 1}, nil, logger.NewNop())
	h.SetSweeper(sw)
	rec := httptest.NewRecorder()
	h.Create(rec, seedReq(http.MethodPost, "/", `{"kind":"root_domain","value":"acme.com","attested":true}`, shared.NewID(), "u"))
	var body ScopeTargetResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusAccepted || body.Status != "pending" || body.ApprovalsRequired != 1 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if len(sw.tenants) != 0 {
		t.Fatal("a pending seed started discovery")
	}
}

func TestEASMSeedHandler_ErrorsMap(t *testing.T) {
	tenant := shared.NewID()
	for name, tc := range map[string]struct {
		err  error
		code int
		want string
	}{
		"validation":    {fmt.Errorf("%w: not a domain name", shared.ErrValidation), http.StatusBadRequest, ""},
		"duplicate":     {fmt.Errorf("%w: exists", shared.ErrConflict), http.StatusConflict, ""},
		"entry exists":  {scopedom.ErrTargetAlreadyExists, http.StatusConflict, ""},
		"member":        {easmapp.ErrSeedNeedsApprover, http.StatusForbidden, "WIDENING_NEEDS_APPROVER"},
		"step-up":       {middleware.ErrStepUpRequired, http.StatusForbidden, string(middleware.CodeStepUpRequired)},
		"step-up unset": {scope.ErrStepUpNotWired, http.StatusForbidden, string(middleware.CodeStepUpUnavailable)},
	} {
		rec := httptest.NewRecorder()
		NewEASMSeedHandler(&fakeSeeder{err: tc.err}, nil, logger.NewNop()).
			Create(rec, seedReq(http.MethodPost, "/x", `{"kind":"root_domain","value":"x","attested":true}`, tenant, ""))
		var e struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		if rec.Code != tc.code || (tc.want != "" && e.Code != tc.want) {
			t.Errorf("%s: %d %q, want %d %q", name, rec.Code, e.Code, tc.code, tc.want)
		}
	}

	// Another tenant's seed id is a 404, with no audit record.
	audit := &fakeAuditor{}
	h := NewEASMSeedHandler(&fakeSeeder{err: shared.ErrNotFound}, audit, logger.NewNop())
	req := seedReq(http.MethodDelete, "/x", "", tenant, "")
	req.SetPathValue("id", shared.NewID().String())
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusNotFound || len(audit.events) != 0 {
		t.Fatalf("foreign delete: %d, %d audit events", rec.Code, len(audit.events))
	}

	rec = httptest.NewRecorder()
	h2 := NewEASMSeedHandler(&fakeSeeder{}, nil, logger.NewNop())
	h2.List(rec, seedReq(http.MethodGet, "/x", "", tenant, ""))
	var body EASMSeedListResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Data == nil {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
}

type recordingSweeper struct{ tenants []shared.ID }

func (r *recordingSweeper) SweepForSeed(id shared.ID) { r.tenants = append(r.tenants, id) }

// research/22 P0-11: a seed in effect starts a sweep for the token's tenant;
// a refused create does not.
func TestEASMSeedHandler_CreateStartsSweep(t *testing.T) {
	tenant := shared.NewID()
	svc := &fakeSeeder{}
	sw := &recordingSweeper{}
	h := NewEASMSeedHandler(svc, nil, logger.NewNop())
	h.SetSweeper(sw)

	rec := httptest.NewRecorder()
	h.Create(rec, seedReq(http.MethodPost, "/", `{"kind":"root_domain","value":"acme.com","attested":true}`, tenant, "u"))
	if rec.Code != http.StatusCreated || len(sw.tenants) != 1 || sw.tenants[0] != tenant {
		t.Fatalf("status %d sweeps %v", rec.Code, sw.tenants)
	}
	svc.err = shared.ErrConflict
	rec = httptest.NewRecorder()
	h.Create(rec, seedReq(http.MethodPost, "/", `{"kind":"root_domain","value":"acme.com","attested":true}`, tenant, "u"))
	if len(sw.tenants) != 1 {
		t.Fatal("a refused create started a sweep")
	}
}

// Turning discovery on is announced to the administrators; other changes
// are not.
func TestEASMSeedHandler_DiscoveryOnNotifiesAdmins(t *testing.T) {
	for _, turnedOn := range []bool{true, false} {
		notes := &seedNotices{}
		h := NewEASMSeedHandler(&fakeSeeder{turnedOn: turnedOn}, nil, logger.NewNop())
		h.SetAdminNotifier(notes)
		req := seedReq(http.MethodPatch, "/x", `{"discovery_enabled":true}`, shared.NewID(), "u")
		req.SetPathValue("id", shared.NewID().String())
		rec := httptest.NewRecorder()
		h.Update(rec, req)
		if rec.Code != http.StatusOK || (len(notes.titles) == 1) != turnedOn {
			t.Fatalf("turnedOn=%v: %d, notices %v", turnedOn, rec.Code, notes.titles)
		}
	}
}
