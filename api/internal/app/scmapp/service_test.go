package scmapp

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/scm/githubapp"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeGitHub struct {
	access   map[string]int64 // code -> installation the code's user can access
	sigOK    bool
	forgot   []int64
	accounts map[int64]string
}

func (f *fakeGitHub) Slug() string { return "openctem" }
func (f *fakeGitHub) InstallURL(state string) string {
	return "https://github.com/apps/openctem/installations/new?state=" + url.QueryEscape(state)
}
func (f *fakeGitHub) GetInstallation(_ context.Context, id int64) (*githubapp.Installation, error) {
	return &githubapp.Installation{ID: id, Account: githubapp.Account{Login: f.accounts[id], ID: id * 10, Type: "Organization"},
		RepositorySelection: "selected"}, nil
}
func (f *fakeGitHub) UserMayBindInstallation(_ context.Context, code string, inst *githubapp.Installation) (bool, error) {
	return f.access[code] == inst.ID, nil
}

type memOnce struct{ seen map[string]bool }

func (m *memOnce) FirstDelivery(_ context.Context, key string, _ time.Duration) (bool, error) {
	if m.seen[key] {
		return false, nil
	}
	m.seen[key] = true
	return true, nil
}
func (f *fakeGitHub) VerifySignature(_ []byte, sig string) bool { return f.sigOK && sig == "good" }
func (f *fakeGitHub) ForgetInstallation(id int64)               { f.forgot = append(f.forgot, id) }

type memRepo struct{ rows []scmapp.Installation }

func (m *memRepo) Create(_ context.Context, inst *scmapp.Installation) error {
	for i := range m.rows {
		if m.rows[i].InstallationID == inst.InstallationID {
			if m.rows[i].TenantID != inst.TenantID {
				return scmapp.ErrBoundElsewhere
			}
			m.rows[i].Status = scmapp.StatusActive
			*inst = m.rows[i]
			return nil
		}
	}
	inst.Status = scmapp.StatusActive
	m.rows = append(m.rows, *inst)
	return nil
}
func (m *memRepo) List(_ context.Context, tid shared.ID) ([]scmapp.Installation, error) {
	var out []scmapp.Installation
	for _, r := range m.rows {
		if r.TenantID == tid {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memRepo) Get(_ context.Context, tid, id shared.ID) (*scmapp.Installation, error) {
	for i := range m.rows {
		if m.rows[i].TenantID == tid && m.rows[i].ID == id {
			return &m.rows[i], nil
		}
	}
	return nil, scmapp.ErrNotFound
}
func (m *memRepo) ActiveForAccount(context.Context, shared.ID, string, string) (*scmapp.Installation, error) {
	return nil, scmapp.ErrNotFound
}
func (m *memRepo) Delete(_ context.Context, tid, id shared.ID) error {
	for i := range m.rows {
		if m.rows[i].TenantID == tid && m.rows[i].ID == id {
			m.rows = append(m.rows[:i], m.rows[i+1:]...)
			return nil
		}
	}
	return scmapp.ErrNotFound
}
func (m *memRepo) GetByInstallationID(_ context.Context, _ string, id int64) (*scmapp.Installation, error) {
	for i := range m.rows {
		if m.rows[i].InstallationID == id {
			return &m.rows[i], nil
		}
	}
	return nil, scmapp.ErrNotFound
}
func (m *memRepo) SetStatusByInstallationID(_ context.Context, _ string, id int64, st string) (int64, error) {
	for i := range m.rows {
		if m.rows[i].InstallationID == id && m.rows[i].Status != st {
			m.rows[i].Status = st
			return 1, nil
		}
	}
	return 0, nil
}

type memAudit struct{ actions []string }

func (a *memAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.actions = append(a.actions, ev.Action.String())
	return nil
}

func stateOf(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state")
}

func TestCompleteGitHubInstallNeedsTheCallersStateAndAccess(t *testing.T) {
	gh := &fakeGitHub{access: map[string]int64{"alice-code": 11, "bob-code": 22}, accounts: map[int64]string{11: "acme", 22: "beta"}}
	repo, audit := &memRepo{}, &memAudit{}
	svc := NewService(repo, gh, "jwt-secret-at-least-32-characters-long", audit, nil)
	ctx := context.Background()
	tenantA, tenantB := shared.NewID(), shared.NewID()
	alice, bob := shared.NewID().String(), shared.NewID().String()

	link, err := svc.GitHubInstallURL(tenantA, alice)
	if err != nil {
		t.Fatal(err)
	}
	state := stateOf(t, link)

	// Another person, another organization, a tampered or expired state: refused.
	for name, in := range map[string]struct {
		tenant shared.ID
		user   string
		state  string
	}{
		"other user":     {tenantA, bob, state},
		"other tenant":   {tenantB, alice, state},
		"tampered state": {tenantA, alice, state + "0"},
		"no state":       {tenantA, alice, ""},
	} {
		if _, err := svc.CompleteGitHubInstall(ctx, in.tenant, CompleteGitHubInput{InstallationID: 11, Code: "alice-code", State: in.state},
			Actor{UserID: in.user}); !errors.Is(err, scmapp.ErrNotAuthorized) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A guessed installation id whose account the person does not own: refused.
	if _, err := svc.CompleteGitHubInstall(ctx, tenantA, CompleteGitHubInput{InstallationID: 22, Code: "alice-code", State: state},
		Actor{UserID: alice}); !errors.Is(err, scmapp.ErrNotAuthorized) {
		t.Fatalf("someone else's installation: %v", err)
	}
	// The real thing: bound and audited.
	inst, err := svc.CompleteGitHubInstall(ctx, tenantA, CompleteGitHubInput{InstallationID: 11, Code: "alice-code", State: state}, Actor{UserID: alice})
	if err != nil || inst.AccountLogin != "acme" || inst.TenantID != tenantA {
		t.Fatalf("install: %+v %v", inst, err)
	}
	if len(audit.actions) != 1 || audit.actions[0] != "scm_app.installed" {
		t.Fatalf("audit = %v", audit.actions)
	}
	// The same installation cannot be bound to a second organization.
	linkB, _ := svc.GitHubInstallURL(tenantB, alice)
	if _, err := svc.CompleteGitHubInstall(ctx, tenantB, CompleteGitHubInput{InstallationID: 11, Code: "alice-code", State: stateOf(t, linkB)},
		Actor{UserID: alice}); !errors.Is(err, scmapp.ErrBoundElsewhere) {
		t.Fatalf("bound elsewhere: %v", err)
	}
	// The state expires.
	svc.SetClock(func() time.Time { return time.Now().Add(StateTTL + time.Minute) })
	if _, err := svc.CompleteGitHubInstall(ctx, tenantA, CompleteGitHubInput{InstallationID: 11, Code: "alice-code", State: state},
		Actor{UserID: alice}); !errors.Is(err, scmapp.ErrNotAuthorized) {
		t.Fatalf("expired state: %v", err)
	}
	svc.SetClock(time.Now)
	// Remove is tenant-scoped.
	if err := svc.Remove(ctx, tenantB, inst.ID, Actor{}); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("cross-tenant remove: %v", err)
	}
	if err := svc.Remove(ctx, tenantA, inst.ID, Actor{UserID: alice}); err != nil || len(gh.forgot) != 1 {
		t.Fatalf("remove: %v %v", err, gh.forgot)
	}
}

func TestGitHubWebhook(t *testing.T) {
	gh := &fakeGitHub{sigOK: true, accounts: map[int64]string{11: "acme"}}
	repo, audit := &memRepo{}, &memAudit{}
	tenant := shared.NewID()
	repo.rows = []scmapp.Installation{{ID: shared.NewID(), TenantID: tenant, Provider: "github", InstallationID: 11, AccountLogin: "acme", Status: "active"}}
	svc := NewService(repo, gh, "s", audit, nil)
	ctx := context.Background()
	if err := svc.HandleGitHubWebhook(ctx, "installation", "bad", []byte(`{"action":"deleted","installation":{"id":11}}`)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("bad signature: %v", err)
	}
	if repo.rows[0].Status != "active" {
		t.Fatal("an unsigned delivery changed the installation")
	}
	if err := svc.HandleGitHubWebhook(ctx, "installation", "good", []byte(`{"action":"suspend","installation":{"id":11}}`)); err != nil || repo.rows[0].Status != "suspended" {
		t.Fatalf("suspend: %v %s", err, repo.rows[0].Status)
	}
	if err := svc.HandleGitHubWebhook(ctx, "installation", "good", []byte(`{"action":"deleted","installation":{"id":11}}`)); err != nil || repo.rows[0].Status != "deleted" {
		t.Fatalf("deleted: %v %s", err, repo.rows[0].Status)
	}
	if len(audit.actions) != 2 {
		t.Fatalf("status changes audited %d times", len(audit.actions))
	}
	// Unknown installations and other events are acknowledged and ignored.
	if err := svc.HandleGitHubWebhook(ctx, "installation", "good", []byte(`{"action":"deleted","installation":{"id":99}}`)); err != nil {
		t.Fatal(err)
	}
	if err := svc.HandleGitHubWebhook(ctx, "push", "good", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Without a GitHub App nothing is accepted.
	if err := NewService(repo, nil, "s", audit, nil).HandleGitHubWebhook(ctx, "installation", "good", nil); !errors.Is(err, githubapp.ErrNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
}

func TestInstallStateIsSingleUse(t *testing.T) {
	gh := &fakeGitHub{access: map[string]int64{"alice-code": 11}, accounts: map[int64]string{11: "acme"}}
	svc := NewService(&memRepo{}, gh, "jwt-secret-at-least-32-characters-long", &memAudit{}, nil)
	svc.SetOnceStore(&memOnce{seen: map[string]bool{}})
	ctx := context.Background()
	tenant, alice := shared.NewID(), shared.NewID().String()

	link, err := svc.GitHubInstallURL(tenant, alice)
	if err != nil {
		t.Fatal(err)
	}
	state := stateOf(t, link)
	in := CompleteGitHubInput{InstallationID: 11, Code: "alice-code", State: state}
	if _, err := svc.CompleteGitHubInstall(ctx, tenant, in, Actor{UserID: alice}); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := svc.CompleteGitHubInstall(ctx, tenant, in, Actor{UserID: alice}); !errors.Is(err, scmapp.ErrNotAuthorized) {
		t.Fatalf("replayed state: %v", err)
	}
	// A failed attempt also spends the state: the person starts again.
	link2, _ := svc.GitHubInstallURL(tenant, alice)
	bad := CompleteGitHubInput{InstallationID: 11, Code: "mallory-code", State: stateOf(t, link2)}
	if _, err := svc.CompleteGitHubInstall(ctx, tenant, bad, Actor{UserID: alice}); !errors.Is(err, scmapp.ErrNotAuthorized) {
		t.Fatalf("not the account owner: %v", err)
	}
	bad.Code = "alice-code"
	if _, err := svc.CompleteGitHubInstall(ctx, tenant, bad, Actor{UserID: alice}); !errors.Is(err, scmapp.ErrNotAuthorized) {
		t.Fatalf("state reused after a refusal: %v", err)
	}
}

type failingOnce struct{}

func (failingOnce) FirstDelivery(context.Context, string, time.Duration) (bool, error) {
	return false, errors.New("redis down")
}

func TestInstallStateStoreDownFailsClosed(t *testing.T) {
	gh := &fakeGitHub{access: map[string]int64{"alice-code": 11}, accounts: map[int64]string{11: "acme"}}
	svc := NewService(&memRepo{}, gh, "jwt-secret-at-least-32-characters-long", &memAudit{}, nil)
	svc.SetOnceStore(failingOnce{})
	tenant, alice := shared.NewID(), shared.NewID().String()
	link, _ := svc.GitHubInstallURL(tenant, alice)
	if _, err := svc.CompleteGitHubInstall(context.Background(), tenant,
		CompleteGitHubInput{InstallationID: 11, Code: "alice-code", State: stateOf(t, link)}, Actor{UserID: alice}); !errors.Is(err, scmapp.ErrNotAuthorized) {
		t.Fatalf("store down: %v", err)
	}
}
