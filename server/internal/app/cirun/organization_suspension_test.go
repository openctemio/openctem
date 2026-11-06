package cirun

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cirundom "github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// tokenRunRepo answers the run token lookup only.
type tokenRunRepo struct {
	cirundom.Repository
	run *cirundom.Run
}

func (r tokenRunRepo) GetRunByTokenHash(context.Context, []byte, time.Time) (*cirundom.Run, error) {
	return r.run, nil
}

type orgGateFunc func(shared.ID) error

func (f orgGateFunc) CheckAccess(_ context.Context, id shared.ID) error { return f(id) }

// A CI run token of a suspended organization is refused; an unreadable
// status refuses too (fail closed).
func TestAuthenticate_SuspendedOrganization(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	run := &cirundom.Run{ID: shared.NewID(), TenantID: tenantID}
	s := NewService(Deps{Repo: tokenRunRepo{run: run}}, Config{}, nil)
	token := cirundom.TokenPrefix + strings.Repeat("a", 43)

	if got, err := s.Authenticate(ctx, token); err != nil || got != run {
		t.Fatalf("no gate: %v", err)
	}
	s.SetOrganizationGate(orgGateFunc(func(id shared.ID) error {
		if id == tenantID {
			return tenantdom.ErrOrganizationSuspended
		}
		return nil
	}))
	if _, err := s.Authenticate(ctx, token); !errors.Is(err, tenantdom.ErrOrganizationSuspended) {
		t.Fatalf("suspended: %v", err)
	}
	s.SetOrganizationGate(orgGateFunc(func(shared.ID) error { return errors.New("db down") }))
	if _, err := s.Authenticate(ctx, token); err == nil {
		t.Fatal("unreadable status admitted the token")
	}
	s.SetOrganizationGate(orgGateFunc(func(shared.ID) error { return nil }))
	if _, err := s.Authenticate(ctx, token); err != nil {
		t.Fatalf("active: %v", err)
	}
}
