package auth

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
)

// memIdentities is an in-memory useridentity.Repository with the same two
// uniqueness rules as the table: one account per (issuer, subject, scope), one
// subject per (account, issuer, scope).
type memIdentities struct {
	mu   sync.Mutex
	rows []*useridentity.Identity
	// hideOnce makes the next N GetByKey calls miss: a concurrent login that
	// binds right after this one looked.
	hideOnce int
}

func newMemIdentities() *memIdentities { return &memIdentities{} }

func sameKey(a, b useridentity.Key) bool { return a.SameIssuer(b) && a.Subject == b.Subject }

// bindTo binds a platform-wide (OIDC) identity, for test setup.
func (m *memIdentities) bindTo(u *userdom.User, issuer, subject string) {
	ident, err := useridentity.New(u.ID(), useridentity.Key{Issuer: issuer, Subject: subject})
	if err != nil {
		panic(err)
	}
	if err := m.Create(context.Background(), ident); err != nil {
		panic(err)
	}
}

// keysOf lists the keys bound to the account.
func (m *memIdentities) keysOf(userID shared.ID) []useridentity.Key {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []useridentity.Key
	for _, r := range m.rows {
		if r.UserID == userID {
			out = append(out, r.Key)
		}
	}
	return out
}

func (m *memIdentities) GetByKey(_ context.Context, key useridentity.Key) (*useridentity.Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hideOnce > 0 {
		m.hideOnce--
		return nil, useridentity.ErrNotFound
	}
	for _, r := range m.rows {
		if sameKey(r.Key, key) {
			c := *r
			return &c, nil
		}
	}
	return nil, useridentity.ErrNotFound
}

func (m *memIdentities) ListByUser(_ context.Context, userID shared.ID) ([]*useridentity.Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*useridentity.Identity
	for _, r := range m.rows {
		if r.UserID == userID {
			c := *r
			out = append(out, &c)
		}
	}
	return out, nil
}

func (m *memIdentities) Create(_ context.Context, ident *useridentity.Identity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if sameKey(r.Key, ident.Key) || (r.UserID == ident.UserID && r.Key.SameIssuer(ident.Key)) {
			return useridentity.ErrConflict
		}
	}
	c := *ident
	m.rows = append(m.rows, &c)
	return nil
}

func (m *memIdentities) ChangeSubject(_ context.Context, id shared.ID, subject string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var target *useridentity.Identity
	for _, r := range m.rows {
		if r.ID == id {
			target = r
		}
	}
	if target == nil {
		return useridentity.ErrNotFound
	}
	next := target.Key
	next.Subject = subject
	for _, r := range m.rows {
		if r != target && sameKey(r.Key, next) {
			return useridentity.ErrConflict
		}
	}
	target.Key = next
	return nil
}

func (m *memIdentities) MarkUsed(_ context.Context, id shared.ID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.ID == id {
			t := at
			r.LastUsedAt = &t
		}
	}
	return nil
}

var _ useridentity.Repository = (*memIdentities)(nil)
