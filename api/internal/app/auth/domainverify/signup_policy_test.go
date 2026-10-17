package domainverify

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// The walk up to parent domains never reaches a public suffix or a shared
// mailbox domain, even when a (legacy) verified claim for one exists.
func TestSignupPolicyForEmail_NeverAPublicSuffix(t *testing.T) {
	ctx := context.Background()
	repo := newMemRepo()
	svc := NewService(repo, &mockResolver{}, nil)
	org := shared.NewID()
	for _, d := range []string{"co.uk", "gmail.com", "github.io"} {
		vd, err := verifieddomain.New(shared.NewID(), org, d, "tok")
		if err != nil {
			t.Fatal(err)
		}
		vd.WithPurpose(verifieddomain.PurposeSSO)
		vd.MarkVerified(time.Now())
		vd.WithSignupPolicy(verifieddomain.SignupPolicy{Join: verifieddomain.JoinAuto, JoinRole: "viewer",
			SSORequired: true, BlockNewWorkspaces: true, IncludeSubdomains: true}, nil)
		_ = repo.Create(ctx, vd)
	}
	for _, email := range []string{"bob@acme.co.uk", "bob@co.uk", "bob@gmail.com", "bob@alice.github.io"} {
		if _, ok, err := svc.SignupPolicyForEmail(ctx, email); ok || err != nil {
			t.Fatalf("%s must not be governed by a public-suffix or consumer claim (ok=%v err=%v)", email, ok, err)
		}
	}

	// A real registrable domain claimed with subdomains still covers them.
	vd, _ := verifieddomain.New(shared.NewID(), org, "acme.co.uk", "tok")
	vd.WithPurpose(verifieddomain.PurposeSSO)
	vd.MarkVerified(time.Now())
	vd.WithSignupPolicy(verifieddomain.SignupPolicy{Join: verifieddomain.JoinOff, JoinRole: "viewer", IncludeSubdomains: true}, nil)
	_ = repo.Create(ctx, vd)
	ep, ok, err := svc.SignupPolicyForEmail(ctx, "eve@eu.acme.co.uk")
	if err != nil || !ok || ep.Domain != "acme.co.uk" {
		t.Fatalf("acme.co.uk with subdomains covers eu.acme.co.uk: %+v %v %v", ep, ok, err)
	}
}
