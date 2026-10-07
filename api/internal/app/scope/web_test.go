package scope

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func pathExclusion(t *testing.T, tenantID shared.ID, host, prefix string, methods []string, testing scopedom.Testing, until *time.Time) *scopedom.Exclusion {
	t.Helper()
	e, err := scopedom.NewExclusion(tenantID, scopedom.ExclusionTypePath, host, "fragile path", nil, "requester")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Approve("approver"); err != nil {
		t.Fatal(err)
	}
	e.SetWeb(&scopedom.WebRule{PathPrefix: prefix, Methods: methods, Testing: testing, TestingUntil: until})
	return e
}

func excludedURLs(t *testing.T, svc *Service, tenantID shared.ID, urls ...string) map[string]bool {
	t.Helper()
	cands := make([]ExclusionCandidate, len(urls))
	byID := map[shared.ID]string{}
	for i, u := range urls {
		cands[i] = ExclusionCandidate{ID: shared.NewID(), Values: []string{u}}
		byID[cands[i].ID] = u
	}
	got, err := svc.ExcludedTargets(context.Background(), tenantID.String(), cands)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for id, ex := range got {
		if ex {
			out[byID[id]] = true
		}
	}
	return out
}

// An exclusion of /admin/debug on every host (U24) drops URL targets under
// it at dispatch, never the host itself.
func TestPathExclusion_DispatchDropsOnlyURLsUnderThePrefix(t *testing.T) {
	tenantID := shared.NewID()
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		pathExclusion(t, tenantID, "*", "/admin/debug", nil, scopedom.TestingBlocked, nil),
	}})
	got := excludedURLs(t, svc, tenantID,
		"app.example.com", "https://app.example.com", "https://app.example.com/admin/debug/x",
		"https://other.example.net/admin/debug", "https://app.example.com/admin/debugger")
	want := map[string]bool{"https://app.example.com/admin/debug/x": true, "https://other.example.net/admin/debug": true}
	if len(got) != len(want) || !got["https://app.example.com/admin/debug/x"] || !got["https://other.example.net/admin/debug"] {
		t.Fatalf("excluded = %v, want %v", got, want)
	}
}

func TestPathExclusion_TestingModes(t *testing.T) {
	tenantID := shared.NewID()
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	target := "https://app.example.com/admin/users"
	for name, c := range map[string]struct {
		e    *scopedom.Exclusion
		want bool
	}{
		"blocked":                {pathExclusion(t, tenantID, "*", "/admin", nil, scopedom.TestingBlocked, nil), true},
		"read_only lets GET":     {pathExclusion(t, tenantID, "*", "/admin", nil, scopedom.TestingReadOnly, nil), false},
		"allowed":                {pathExclusion(t, tenantID, "*", "/admin", nil, scopedom.TestingAllowed, &future), false},
		"allowed past its until": {pathExclusion(t, tenantID, "*", "/admin", nil, scopedom.TestingAllowed, &past), true},
		"method-scoped writes":   {pathExclusion(t, tenantID, "*", "/admin", []string{"POST", "DELETE"}, scopedom.TestingBlocked, nil), false},
	} {
		svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{c.e}})
		if got := excludedURLs(t, svc, tenantID, target)[target]; got != c.want {
			t.Errorf("%s: excluded = %v, want %v", name, got, c.want)
		}
	}
}

func TestBuildWebScope(t *testing.T) {
	tenantID := shared.NewID()
	future := time.Now().Add(time.Hour)
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		pathExclusion(t, tenantID, "*", "/logout", nil, scopedom.TestingBlocked, nil),
		pathExclusion(t, tenantID, "*.example.com", "/admin/debug", nil, scopedom.TestingBlocked, nil),
		pathExclusion(t, tenantID, "shop.example.org", "/orders", []string{"POST", "DELETE"}, scopedom.TestingBlocked, nil),
		pathExclusion(t, tenantID, "*", "/staging-only", nil, scopedom.TestingAllowed, &future),
	}})
	ctx := context.Background()

	ws, err := svc.BuildWebScope(ctx, tenantID, []string{"https://app.example.com"})
	if err != nil || ws == nil || !slices.Equal(ws.DenyPaths, []string{"/admin/debug", "/logout"}) || len(ws.Methods) != 0 {
		t.Fatalf("app.example.com scope = %+v, %v", ws, err)
	}
	// A write-only rule keeps the path readable and limits the job to GET/HEAD.
	ws, err = svc.BuildWebScope(ctx, tenantID, []string{"https://shop.example.org"})
	if err != nil || ws == nil || !slices.Equal(ws.DenyPaths, []string{"/logout"}) || !slices.Equal(ws.Methods, []string{"GET", "HEAD"}) {
		t.Fatalf("shop scope = %+v, %v", ws, err)
	}
	// Nothing applies: no web scope at all.
	svc = newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{
		pathExclusion(t, tenantID, "other.example.net", "/x", nil, scopedom.TestingBlocked, nil),
	}})
	if ws, err := svc.BuildWebScope(ctx, tenantID, []string{"https://app.example.com"}); err != nil || ws != nil {
		t.Fatalf("unrelated rule: %+v, %v", ws, err)
	}
	// A failed lookup refuses (fail closed).
	svc = newFilterService(&fakeExclusionRepo{err: errors.New("db down")})
	if _, err := svc.BuildWebScope(ctx, tenantID, []string{"https://app.example.com"}); err == nil {
		t.Fatal("a failed lookup built a web scope")
	}
}

func TestWebRules_BlockingIsPerMethod(t *testing.T) {
	tenantID := shared.NewID()
	e := pathExclusion(t, tenantID, "*", "/admin", []string{"POST"}, scopedom.TestingBlocked, nil)
	svc := newFilterService(&fakeExclusionRepo{active: []*scopedom.Exclusion{e}})
	rules, err := svc.LoadWebRules(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if got := rules.Blocking("https://app.example.com", "POST", "/admin/save"); got == nil || got.ID() != e.ID() {
		t.Fatal("a POST endpoint under a POST rule must be blocked, naming the rule")
	}
	if rules.Blocking("https://app.example.com", "GET", "/admin/save") != nil {
		t.Fatal("a GET endpoint under a POST-only rule is testable")
	}
	var none *WebRules
	if none.Blocking("https://app.example.com", "GET", "/admin") != nil {
		t.Fatal("nil rules")
	}
}

// testingRepo is an exclusion repository with GetByID and SetTesting.
type testingRepo struct {
	scopedom.ExclusionRepository
	byID map[shared.ID]*scopedom.Exclusion
}

func (r *testingRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*scopedom.Exclusion, error) {
	e, ok := r.byID[id]
	if !ok || e.TenantID() != tenantID {
		return nil, scopedom.ErrExclusionNotFound
	}
	return e, nil
}

func (r *testingRepo) SetTesting(_ context.Context, tenantID, id shared.ID, rule *scopedom.WebRule) error {
	e, ok := r.byID[id]
	if !ok || e.TenantID() != tenantID {
		return scopedom.ErrExclusionNotFound
	}
	cp := *rule
	e.SetWeb(&cp)
	return nil
}

type admins struct{ ids []shared.ID }

func (a admins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) { return a.ids, nil }

type notices struct {
	sent []notificationdom.NotificationParams
}

func (n *notices) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.sent = append(n.sent, p)
	return nil
}

func TestSetExclusionTesting(t *testing.T) {
	tenantID, other := shared.NewID(), shared.NewID()
	path := pathExclusion(t, tenantID, "*", "/admin", nil, scopedom.TestingBlocked, nil)
	domain := newExclusion(t, tenantID, "x.example.com")
	repo := &testingRepo{byID: map[shared.ID]*scopedom.Exclusion{path.ID(): path, domain.ID(): domain}}
	svc := newFilterService(repo)
	n := &notices{}
	svc.SetNotifications(admins{ids: []shared.ID{shared.NewID(), shared.NewID()}}, n)
	ctx := context.Background()
	in := func(tenant shared.ID, id shared.ID, mode string, until *time.Time) SetTestingInput {
		return SetTestingInput{TenantID: tenant.String(), ExclusionID: id.String(), Testing: mode, TestingUntil: until, ChangedBy: "approver-2"}
	}

	until := time.Now().Add(24 * time.Hour)
	_, after, err := svc.ChangeExclusionTesting(ctx, in(tenantID, path.ID(), "allowed", &until))
	if err != nil {
		t.Fatal(err)
	}
	if w := after.Web(); w.Testing != scopedom.TestingAllowed || w.TestingUntil == nil || w.TestingChangedBy != "approver-2" || w.TestingChangedAt == nil {
		t.Fatalf("after = %+v", w)
	}
	if len(n.sent) != 2 {
		t.Fatalf("%d admin notices, want 2", len(n.sent))
	}

	// blocked drops the deadline.
	if _, after, err = svc.ChangeExclusionTesting(ctx, in(tenantID, path.ID(), "blocked", &until)); err != nil || after.Web().TestingUntil != nil {
		t.Fatalf("blocked: %+v %v", after, err)
	}

	tooFar, past := time.Now().Add(100*24*time.Hour), time.Now().Add(-time.Hour)
	for name, c := range map[string]SetTestingInput{
		"unknown mode":      in(tenantID, path.ID(), "everything", nil),
		"until in the past": in(tenantID, path.ID(), "allowed", &past),
		"until too far":     in(tenantID, path.ID(), "read_only", &tooFar),
		"not a path rule":   in(tenantID, domain.ID(), "allowed", nil),
	} {
		if _, _, err := svc.ChangeExclusionTesting(ctx, c); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
	if _, _, err := svc.ChangeExclusionTesting(ctx, in(other, path.ID(), "allowed", nil)); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("another tenant: err = %v, want not found", err)
	}
}
