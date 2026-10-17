package apikey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/crypto"
	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type oneKeyRepo struct {
	apikeydom.Repository
	key *apikeydom.APIKey
}

func (r oneKeyRepo) GetByHash(context.Context, string) (*apikeydom.APIKey, error)      { return r.key, nil }
func (r oneKeyRepo) TouchLastUsed(context.Context, shared.ID, shared.ID, string) error { return nil }

// A key with no user would read every asset of the tenant: it is refused at
// authentication, while a user-bound key still authenticates.
func TestAuthenticate_RefusesUserlessKey(t *testing.T) {
	raw := "oct_" + "abcdefghijklmnopqrstuvwxyz012345"
	mk := func(uid *shared.ID) *apikeydom.APIKey {
		return apikeydom.Reconstruct(shared.NewID(), shared.NewID(), uid, "k", "", crypto.HashTokenPeppered(raw, ""), "oct_abcd",
			[]string{"assets:read"}, 100, apikeydom.StatusActive, nil, nil, "", 0, nil, time.Now(), time.Now(), nil, nil)
	}
	uid := shared.NewID()
	s := NewService(oneKeyRepo{key: mk(nil)}, "", logger.NewNop())
	if _, err := s.Authenticate(context.Background(), raw, "192.0.2.1"); !errors.Is(err, apikeydom.ErrAPIKeyNotFound) {
		t.Fatalf("user-less key: err = %v, want ErrAPIKeyNotFound", err)
	}
	s = NewService(oneKeyRepo{key: mk(&uid)}, "", logger.NewNop())
	if _, err := s.Authenticate(context.Background(), raw, "192.0.2.1"); err != nil {
		t.Fatalf("user-bound key refused: %v", err)
	}
}
