package tenant

import (
	"context"
	"strings"

	"github.com/openctemio/api/pkg/domain/shared"
	userdom "github.com/openctemio/api/pkg/domain/user"
)

// UserDisplayNames resolves a user's display name for invitation emails and
// the public invitation preview. It returns the name only: an account created
// without a name stores its email there, and an email is never returned (the
// preview is unauthenticated).
type UserDisplayNames struct {
	users userdom.Repository
}

// NewUserDisplayNames returns a UserInfoProvider backed by the user repository.
func NewUserDisplayNames(users userdom.Repository) *UserDisplayNames {
	return &UserDisplayNames{users: users}
}

// GetUserNameByID returns the user's display name, or "" when the user has no
// name other than an email address.
func (p *UserDisplayNames) GetUserNameByID(ctx context.Context, id shared.ID) (string, error) {
	u, err := p.users.GetByID(ctx, id)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(u.Name())
	if strings.Contains(name, "@") {
		return "", nil
	}
	return name, nil
}

var _ UserInfoProvider = (*UserDisplayNames)(nil)
