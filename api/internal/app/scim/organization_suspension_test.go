package scim

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scimtoken"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// suspendedGate refuses the organizations it lists; read errors with err.
type suspendedGate struct {
	suspended map[shared.ID]bool
	err       error
}

func (g suspendedGate) CheckAccess(_ context.Context, id shared.ID) error {
	if g.err != nil {
		return g.err
	}
	if g.suspended[id] {
		return tenantdom.ErrOrganizationSuspended
	}
	return nil
}

// A SCIM token of a suspended organization is refused (the IdP is told why);
// an unreadable status refuses it like an unknown token (fail closed).
func TestTokenAuthenticate_SuspendedOrganization(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTokenSvc()
	tenantID := shared.NewID()
	res, err := svc.Mint(ctx, tenantID, "okta", nil)
	if err != nil {
		t.Fatal(err)
	}

	svc.SetOrganizationGate(suspendedGate{suspended: map[shared.ID]bool{tenantID: true}})
	if _, err := svc.Authenticate(ctx, res.Plaintext); !errors.Is(err, tenantdom.ErrOrganizationSuspended) {
		t.Fatalf("suspended: %v", err)
	}
	svc.SetOrganizationGate(suspendedGate{err: errors.New("db down")})
	if _, err := svc.Authenticate(ctx, res.Plaintext); !errors.Is(err, scimtoken.ErrNotFound) {
		t.Fatalf("unreadable status: %v", err)
	}
	// Another organization's suspension does not touch this one.
	svc.SetOrganizationGate(suspendedGate{suspended: map[shared.ID]bool{shared.NewID(): true}})
	if _, err := svc.Authenticate(ctx, res.Plaintext); err != nil {
		t.Fatalf("active: %v", err)
	}
}
