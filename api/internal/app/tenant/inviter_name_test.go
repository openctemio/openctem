package tenant

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

type nameUsers struct {
	userdom.Repository
	byID map[shared.ID]*userdom.User
}

func (r nameUsers) GetByID(_ context.Context, id shared.ID) (*userdom.User, error) {
	if u, ok := r.byID[id]; ok {
		return u, nil
	}
	return nil, shared.ErrNotFound
}

// The invitation preview is public, so the inviter is named by display name
// only. An account without a real name stores its email as the name; that is
// never returned.
func TestUserDisplayNames(t *testing.T) {
	named, err := userdom.NewProvisionedLocalUser("alice@corp.com", "Alice Nguyen")
	if err != nil {
		t.Fatal(err)
	}
	emailNamed, err := userdom.NewProvisionedLocalUser("bob@corp.com", "bob@corp.com")
	if err != nil {
		t.Fatal(err)
	}
	p := NewUserDisplayNames(nameUsers{byID: map[shared.ID]*userdom.User{
		named.ID(): named, emailNamed.ID(): emailNamed,
	}})
	ctx := context.Background()

	if got, err := p.GetUserNameByID(ctx, named.ID()); err != nil || got != "Alice Nguyen" {
		t.Errorf("named user: got %q, %v", got, err)
	}
	if got, _ := p.GetUserNameByID(ctx, emailNamed.ID()); got != "" {
		t.Errorf("an email must never be returned as a display name, got %q", got)
	}
	if got, err := p.GetUserNameByID(ctx, shared.NewID()); err == nil || got != "" {
		t.Errorf("unknown user: got %q, %v", got, err)
	}
}
