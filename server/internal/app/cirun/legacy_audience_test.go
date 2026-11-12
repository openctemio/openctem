package cirun

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/oidc"
)

type audienceRepo struct {
	cirun.Repository
	exists, upgraded bool
}

func (r audienceRepo) PipelineAudienceState(context.Context, shared.ID, cirun.PipelineKey) (bool, bool, error) {
	return r.exists, r.upgraded, nil
}

// A configuration moved to a tenant-bound audience still admits its old
// audience, but only for a pipeline that existed before and has not used the
// new audience yet, and only until the transition ends.
func TestLegacyAudienceTransition(t *testing.T) {
	now := time.Now()
	until := now.Add(24 * time.Hour)
	tenant := shared.NewID()
	cfg := cirun.TrustConfig{ID: shared.NewID(), TenantID: tenant, Provider: cirun.ProviderGitHub, Issuer: cirun.GitHubIssuer,
		Audience: cirun.DefaultAudience(tenant), LegacyAudience: "https://openctem.example.com", LegacyAudienceUntil: &until,
		Rules: cirun.Rules{Owners: []string{"acme"}}, Enabled: true}
	tok := &oidc.WorkloadToken{Issuer: cirun.GitHubIssuer}
	claims := cirun.Claims{Provider: cirun.ProviderGitHub, Repository: "acme/api", RepositoryID: "1", Ref: "refs/heads/main", SHA: "abc", Event: "push", RunID: "9", JTI: "j1"}

	claims.Audience = cfg.LegacyAudience
	if got, refusals := admit([]cirun.TrustConfig{cfg}, tok, claims, now); got == nil {
		t.Fatalf("legacy audience not admitted during the transition: %+v", refusals)
	}
	if got, _ := admit([]cirun.TrustConfig{cfg}, tok, claims, until.Add(time.Second)); got != nil {
		t.Fatal("legacy audience admitted after the transition")
	}
	claims.Audience = "https://other.example.com"
	if got, _ := admit([]cirun.TrustConfig{cfg}, tok, claims, now); got != nil {
		t.Fatal("an unrelated audience was admitted")
	}

	key := cirun.PipelineKey{Provider: cirun.ProviderGitHub, Issuer: cirun.GitHubIssuer, ExternalRepoID: "1", WorkflowPath: ".github/workflows/a.yml"}
	for _, c := range []struct {
		name             string
		exists, upgraded bool
		refused          bool
	}{
		{"existing pipeline, not moved yet", true, false, false},
		{"pipeline already used the new audience", true, true, true},
		{"new pipeline", false, false, true},
	} {
		s := &Service{repo: audienceRepo{exists: c.exists, upgraded: c.upgraded}}
		r, err := s.checkLegacyAudience(context.Background(), tenant, &cfg, key)
		if err != nil {
			t.Fatal(err)
		}
		if (r != nil) != c.refused || (r != nil && r.Code != "legacy_audience") {
			t.Errorf("%s: refusal = %+v", c.name, r)
		}
	}
}
