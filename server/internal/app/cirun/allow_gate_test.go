package cirun

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// allowRepo answers one refusal and one configuration.
type allowRepo struct {
	cirun.Repository
	ref cirun.TokenRefusal
	cfg cirun.TrustConfig
}

func (r allowRepo) TokenRefusal(context.Context, shared.ID, shared.ID) (*cirun.TokenRefusal, error) {
	return &r.ref, nil
}

func (r allowRepo) GetTrustConfig(context.Context, shared.ID, shared.ID) (*cirun.TrustConfig, error) {
	return &r.cfg, nil
}

// Review finding R2: on an all-projects configuration the owner and
// repository rules are skipped, so a stranger's project can produce a
// ref_not_allowed refusal; one click must not add its ref to the rules of
// every approved project. The gate refuses it before anything changes.
func TestAllowInTrustConfig_RefusesAnUnapprovedRepository(t *testing.T) {
	cfgID := shared.NewID()
	repo := allowRepo{
		cfg: cirun.TrustConfig{ID: cfgID, Issuer: "https://gitlab.example.com"},
		ref: cirun.TokenRefusal{Repository: "stranger/app", Ref: "refs/heads/evil", Issuer: "https://gitlab.example.com",
			Configs: []cirun.RefusalConfig{{ID: cfgID.String(), Code: cirun.RefuseRef}}},
	}
	s := &Service{repo: repo}
	var asked string
	s.SetAllowRepositoryGate(func(_ context.Context, _ shared.ID, _ *cirun.TrustConfig, repository string) (bool, error) {
		asked = repository
		return false, nil
	})
	_, _, changed, err := s.AllowInTrustConfig(context.Background(), shared.NewID(), cfgID, shared.NewID(), Actor{})
	if !errors.Is(err, ErrAllowRepositoryNotApproved) || changed {
		t.Fatalf("err %v changed %v, want ErrAllowRepositoryNotApproved", err, changed)
	}
	if asked != "stranger/app" {
		t.Fatalf("the gate was asked about %q, want the refusal's repository", asked)
	}
	// A failing gate is an error, never an approval.
	s.SetAllowRepositoryGate(func(context.Context, shared.ID, *cirun.TrustConfig, string) (bool, error) {
		return false, errors.New("store down")
	})
	if _, _, _, err := s.AllowInTrustConfig(context.Background(), shared.NewID(), cfgID, shared.NewID(), Actor{}); err == nil ||
		errors.Is(err, ErrAllowRepositoryNotApproved) {
		t.Fatalf("a gate failure must surface as its own error, got %v", err)
	}
}

// The gate the server wires (SetAllowRepositoryGate(ApprovedRepositoryGate)):
// a configuration naming its owners and repositories already admitted the
// refused project; an all-projects configuration passes only a project it
// has approved (owner or repository), never a pending, new or blocked one.
func TestApprovedRepositoryGate(t *testing.T) {
	named := &cirun.TrustConfig{Rules: cirun.Rules{Owners: []string{"acme"}}}
	all := &cirun.TrustConfig{Rules: cirun.Rules{AllRepositories: true,
		Owners: []string{"acme"}, Repositories: []string{"data/api", "tools/**"}}}
	cases := []struct {
		name string
		cfg  *cirun.TrustConfig
		repo string
		want bool
	}{
		{"named owners: any refusal's project was admitted by the owner rule", named, "acme/app", true},
		{"all projects: approved group", all, "acme/app", true},
		{"all projects: approved group, upper case path", all, "ACME/App", true},
		{"all projects: approved project", all, "data/api", true},
		{"all projects: approved pattern", all, "tools/linter", true},
		{"all projects: a stranger's project", all, "stranger/app", false},
		{"all projects: another project of an unapproved group", all, "data/other", false},
		{"all projects: no repository on the record", all, "", false},
	}
	for _, c := range cases {
		got, err := ApprovedRepositoryGate(context.Background(), shared.NewID(), c.cfg, c.repo)
		if err != nil || got != c.want {
			t.Errorf("%s: got %v, %v want %v", c.name, got, err, c.want)
		}
	}
}

// With the server's gate wired, an all-projects configuration refuses the
// one-click fix for a project it has not approved, before anything changes.
func TestAllowInTrustConfig_ServerGateRefusesAStrangerOnAllProjects(t *testing.T) {
	cfgID := shared.NewID()
	repo := allowRepo{
		cfg: cirun.TrustConfig{ID: cfgID, Issuer: "https://gitlab.example.com",
			Rules: cirun.Rules{AllRepositories: true, Owners: []string{"acme"}}},
		ref: cirun.TokenRefusal{Repository: "stranger/app", Ref: "refs/heads/evil", Issuer: "https://gitlab.example.com",
			Configs: []cirun.RefusalConfig{{ID: cfgID.String(), Code: cirun.RefuseRef}}},
	}
	s := &Service{repo: repo}
	s.SetAllowRepositoryGate(ApprovedRepositoryGate)
	_, _, changed, err := s.AllowInTrustConfig(context.Background(), shared.NewID(), cfgID, shared.NewID(), Actor{})
	if !errors.Is(err, ErrAllowRepositoryNotApproved) || changed {
		t.Fatalf("err %v changed %v, want ErrAllowRepositoryNotApproved", err, changed)
	}
}
