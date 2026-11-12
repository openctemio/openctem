package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/taggov"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type govByTenant struct {
	sets map[shared.ID]taggov.Set
	err  error
}

func (g govByTenant) For(_ context.Context, t shared.ID) (taggov.Set, error) { return g.sets[t], g.err }

func callerCtx(admin bool, perms ...string) context.Context {
	ctx := context.WithValue(context.Background(), middleware.IsAdminKey, admin)
	return context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
}

// S1/S2: assets:write alone cannot change a tag a rule reads. The approval
// rule's tags need an administrator, the team rule's tags need team:groups:write,
// and another tenant's rules never apply.
func TestCheckTagChange(t *testing.T) {
	ta, tb := shared.NewID(), shared.NewID()
	g := govByTenant{sets: map[shared.ID]taggov.Set{ta: taggov.NewSet([]taggov.Ref{
		{Tag: "production", Req: taggov.Requirement{Rule: taggov.RuleScanApproval, AdminOnly: true}},
		{Tag: "team:payments", Req: taggov.Requirement{Rule: taggov.RuleAccessScope, Permission: "team:groups:write"}},
	})}}
	writer := callerCtx(false, "assets:write")
	groups := callerCtx(false, "assets:write", "team:groups:write")
	admin := callerCtx(true)

	// Removing the production tag to escape the approval rule.
	if _, ref := checkTagChange(writer, g, ta.String(), []string{"production", "x"}, []string{"x"}); ref == nil || ref.status != http.StatusForbidden {
		t.Fatalf("assets:write removed a tag the approval rule reads: %+v", ref)
	}
	// Adding a tag a team rule matches, to pull an asset into the team.
	if _, ref := checkTagChange(writer, g, ta.String(), nil, []string{"team:payments"}); ref == nil || ref.status != http.StatusForbidden {
		t.Fatalf("assets:write added a tag a team rule matches: %+v", ref)
	}
	// Another value of a governing key counts too.
	if _, ref := checkTagChange(writer, g, ta.String(), nil, []string{"team:other"}); ref == nil {
		t.Fatal("the key of a governing tag is governing")
	}
	// The rule's own permission is enough for a team rule, not for the approval rule.
	if ch, ref := checkTagChange(groups, g, ta.String(), nil, []string{"team:payments"}); ref != nil || len(ch) != 1 {
		t.Fatalf("team:groups:write may set the team tag: %+v %v", ref, ch)
	}
	if _, ref := checkTagChange(groups, g, ta.String(), []string{"production"}, nil); ref == nil {
		t.Fatal("team:groups:write must not remove an approval-rule tag")
	}
	if ch, ref := checkTagChange(admin, g, ta.String(), []string{"production"}, nil); ref != nil || len(ch) != 1 {
		t.Fatalf("an administrator may, and it is reported for the audit: %+v %v", ref, ch)
	}
	// Ungoverned tags and unchanged sets need nothing.
	if ch, ref := checkTagChange(writer, g, ta.String(), []string{"production"}, []string{"production", "free"}); ref != nil || len(ch) != 0 {
		t.Fatalf("an ungoverned addition: %+v %v", ref, ch)
	}
	// Cross-tenant: tenant B has no such rules.
	if _, ref := checkTagChange(writer, g, tb.String(), []string{"production"}, nil); ref != nil {
		t.Fatalf("tenant A's rules applied to tenant B: %+v", ref)
	}
	// Fail closed when the rules cannot be read.
	bad := govByTenant{err: errors.New("db down")}
	if _, ref := checkTagChange(writer, bad, ta.String(), nil, []string{"anything"}); ref == nil || ref.status != http.StatusServiceUnavailable {
		t.Fatalf("must fail closed: %+v", ref)
	}
	// No governor wired (tests, stubs): no extra check.
	if _, ref := checkTagChange(writer, nil, ta.String(), []string{"production"}, nil); ref != nil {
		t.Fatal("nil governor")
	}
}

// A case change of a governing tag is a change: it needs the rule's permission.
func TestCheckTagChange_CaseChangeOfAGoverningTag(t *testing.T) {
	ta := shared.NewID()
	g := govByTenant{sets: map[shared.ID]taggov.Set{ta: taggov.NewSet([]taggov.Ref{
		{Tag: "env:prod", Req: taggov.Requirement{Rule: taggov.RuleAccessScope, Permission: "team:groups:write"}},
	})}}
	if _, ref := checkTagChange(callerCtx(false, "assets:write"), g, ta.String(), []string{"env:prod"}, []string{"Env:Prod"}); ref == nil || ref.status != http.StatusForbidden {
		t.Fatalf("a case change slipped past the check: %+v", ref)
	}
}

// An API key or an MCP token never sets a tag a rule reads, whatever
// permissions or role its user holds; a session of the same user may.
func TestCheckTagChange_DelegatedCredentialIsRefused(t *testing.T) {
	ta := shared.NewID()
	g := govByTenant{sets: map[shared.ID]taggov.Set{ta: taggov.NewSet([]taggov.Ref{
		{Tag: "team:payments", Req: taggov.Requirement{Rule: taggov.RuleAccessScope, Permission: "team:groups:write"}},
	})}}
	session := callerCtx(true, "assets:write", "team:groups:write")
	if _, ref := checkTagChange(session, g, ta.String(), nil, []string{"team:payments"}); ref != nil {
		t.Fatalf("a signed-in administrator is allowed: %+v", ref)
	}
	for _, provider := range []string{middleware.AuthProviderAPIKey, middleware.AuthProviderMCPOAuth} {
		ctx := context.WithValue(session, middleware.AuthProviderKey, provider)
		_, ref := checkTagChange(ctx, g, ta.String(), nil, []string{"team:payments"})
		if ref == nil || ref.status != http.StatusForbidden {
			t.Fatalf("%s credential set a governing tag: %+v", provider, ref)
		}
		if strings.Contains(ref.message, "team:payments") {
			t.Fatalf("the refusal names the tag: %q", ref.message)
		}
		// An ungoverned change is still fine for the credential.
		if _, ref := checkTagChange(ctx, g, ta.String(), nil, []string{"free"}); ref != nil {
			t.Fatalf("%s credential refused for an ungoverned tag: %+v", provider, ref)
		}
	}
}
