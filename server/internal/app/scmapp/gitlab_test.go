package scmapp

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/scm/gitlabapi"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeGitLab struct {
	token  gitlabapi.TokenInfo
	member bool
	user   *gitlabapi.User
}

func (f *fakeGitLab) CurrentUser(context.Context) (*gitlabapi.User, error) {
	if f.user != nil {
		u := *f.user
		return &u, nil
	}
	return &gitlabapi.User{ID: f.token.UserID, Username: "group_55_bot", Bot: true}, nil
}

func (f *fakeGitLab) Token(context.Context) (*gitlabapi.TokenInfo, error) {
	t := f.token
	return &t, nil
}
func (f *fakeGitLab) Group(_ context.Context, p string) (*gitlabapi.Group, error) {
	return &gitlabapi.Group{ID: 55, FullPath: strings.ToLower(p)}, nil
}
func (f *fakeGitLab) GroupMember(context.Context, int64, int64) (bool, error) { return f.member, nil }
func (f *fakeGitLab) MergeRequest(context.Context, string, int) (*gitlabapi.MergeRequest, error) {
	return nil, nil
}
func (f *fakeGitLab) SetCommitStatus(context.Context, string, string, string, string, string, string, int64) error {
	return nil
}
func (f *fakeGitLab) UpsertMergeRequestNote(context.Context, string, int, int64, string, string) error {
	return nil
}

type memGitLab struct{ rows []scmapp.GitLabConnection }

func (m *memGitLab) CreateGitLab(_ context.Context, c *scmapp.GitLabConnection) error {
	m.rows = append(m.rows, *c)
	return nil
}
func (m *memGitLab) ListGitLab(_ context.Context, tid shared.ID) ([]scmapp.GitLabConnection, error) {
	var out []scmapp.GitLabConnection
	for _, r := range m.rows {
		if r.TenantID == tid {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memGitLab) DeleteGitLab(_ context.Context, tid, id shared.ID) (*scmapp.GitLabConnection, error) {
	for i, r := range m.rows {
		if r.TenantID == tid && r.ID == id {
			m.rows = append(m.rows[:i], m.rows[i+1:]...)
			return &r, nil
		}
	}
	return nil, scmapp.ErrNotFound
}
func (m *memGitLab) GitLabForProject(_ context.Context, tid shared.ID, host, project string) (*scmapp.GitLabConnection, error) {
	for i := range m.rows {
		if m.rows[i].TenantID == tid && m.rows[i].Covers(host, project) {
			return &m.rows[i], nil
		}
	}
	return nil, scmapp.ErrNotFound
}

func TestConnectGitLabChecksTheTokenAndSealsIt(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	enc, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gl := &fakeGitLab{token: gitlabapi.TokenInfo{Active: true, Scopes: []string{"api"}, UserID: 9, ExpiresAt: "2027-01-31"}, member: true}
	var gotHost, gotToken string
	repo, audit := &memGitLab{}, &memAudit{}
	svc := NewService(&memRepo{}, nil, "s", audit, nil)
	svc.SetGitLab(repo, enc, func(host, token string) (GitLabAPI, error) {
		gotHost, gotToken = host, token
		return gl, nil
	})
	ctx := context.Background()
	tenant, other := shared.NewID(), shared.NewID()
	in := ConnectGitLabInput{Host: "https://GitLab.Example.com/", Group: "Acme/Platform", Token: "glpat-secret"}

	for name, mutate := range map[string]func(){
		"inactive":   func() { gl.token.Active = false },
		"no api":     func() { gl.token.Scopes = []string{"read_api"} },
		"not member": func() { gl.member = false },
		// A person's own token: active, api scope, a direct member, but a
		// person, not a group access token's bot.
		"personal token": func() { gl.user = &gitlabapi.User{ID: 9, Username: "alice", Bot: false} },
		"other user":     func() { gl.user = &gitlabapi.User{ID: 10, Username: "group_55_bot", Bot: true} },
	} {
		gl.token = gitlabapi.TokenInfo{Active: true, Scopes: []string{"api"}, UserID: 9}
		gl.member = true
		gl.user = nil
		mutate()
		if _, err := svc.ConnectGitLab(ctx, tenant, in, Actor{}); !errors.Is(err, ErrInvalidGitLabToken) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := svc.ConnectGitLab(ctx, tenant, ConnectGitLabInput{Host: "evil.example/x", Group: "a", Token: "t"}, Actor{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad host: %v", err)
	}
	gl.token = gitlabapi.TokenInfo{Active: true, Scopes: []string{"api"}, UserID: 9, ExpiresAt: "2027-01-31"}
	gl.member = true
	gl.user = nil // the loop above ends on a random case (map order)
	c, err := svc.ConnectGitLab(ctx, tenant, in, Actor{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if gotHost != "gitlab.example.com" || gotToken != "glpat-secret" || c.GroupPath != "acme/platform" || c.TokenExpiresAt == nil {
		t.Fatalf("connection = %+v host=%s", c, gotHost)
	}
	if strings.Contains(repo.rows[0].TokenEncrypted, "glpat-secret") {
		t.Fatal("the token is stored in clear")
	}
	if len(audit.actions) != 1 {
		t.Fatalf("audit = %v", audit.actions)
	}
	// The decoration opens it for a project of the group, never another
	// tenant's or another group's.
	gotToken = ""
	if _, uid, err := svc.GitLabClientFor(ctx, tenant, "gitlab.example.com", "acme/platform/api"); err != nil || uid != 9 || gotToken != "glpat-secret" {
		t.Fatalf("client for project: %d %v %q", uid, err, gotToken)
	}
	if _, _, err := svc.GitLabClientFor(ctx, other, "gitlab.example.com", "acme/platform/api"); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
	if _, _, err := svc.GitLabClientFor(ctx, tenant, "gitlab.example.com", "acme/platformx/api"); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("sibling group: %v", err)
	}
	if err := svc.RemoveGitLab(ctx, other, c.ID, Actor{}); !errors.Is(err, scmapp.ErrNotFound) {
		t.Fatalf("cross-tenant remove: %v", err)
	}
	if err := svc.RemoveGitLab(ctx, tenant, c.ID, Actor{}); err != nil {
		t.Fatal(err)
	}
}
