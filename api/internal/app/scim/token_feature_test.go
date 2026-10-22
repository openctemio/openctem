package scim

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type scimGate struct {
	allowed map[shared.ID]bool
	err     error
}

func (g scimGate) Allowed(_ context.Context, id shared.ID, f string) (bool, error) {
	if f != limits.FeatureSCIM {
		return false, errors.New("unexpected feature " + f)
	}
	return g.allowed[id], g.err
}

// A new SCIM token is new configuration: it needs scim allowed for the
// organization (a read error refuses too), and nothing is stored otherwise.
func TestMintRefusedWithoutSCIMFeature(t *testing.T) {
	svc, repo := newTokenSvc()
	tid := shared.NewID()

	svc.SetFeatureGate(scimGate{})
	_, err := svc.Mint(context.Background(), tid, "idp", nil)
	var fd *limits.ErrFeatureDenied
	if !errors.As(err, &fd) || fd.Feature != limits.FeatureSCIM || fd.Unavailable {
		t.Fatalf("got %v, want the scim refusal", err)
	}

	svc.SetFeatureGate(scimGate{err: errors.New("db down")})
	if _, err := svc.Mint(context.Background(), tid, "idp", nil); !errors.As(err, &fd) || !fd.Unavailable {
		t.Fatalf("got %v, want a fail-closed refusal", err)
	}
	if got, _ := repo.ListByTenant(context.Background(), tid); len(got) != 0 {
		t.Fatalf("nothing may be stored, got %d tokens", len(got))
	}

	svc.SetFeatureGate(scimGate{allowed: map[shared.ID]bool{tid: true}})
	if _, err := svc.Mint(context.Background(), tid, "idp", nil); err != nil {
		t.Fatalf("an organization with scim must mint: %v", err)
	}
}
