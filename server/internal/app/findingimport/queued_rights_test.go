package findingimport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeKeys struct {
	key *apikey.APIKey
	err error
}

func (f fakeKeys) GetByID(context.Context, shared.ID, shared.ID) (*apikey.APIKey, error) {
	return f.key, f.err
}

type fakePerms struct {
	held bool
	err  error
}

func (f fakePerms) HasPermission(context.Context, string, string, string) (bool, error) {
	return f.held, f.err
}

func keyWith(t *testing.T, tid shared.ID, revoked bool, scopes ...string) *apikey.APIKey {
	t.Helper()
	k := apikey.NewAPIKey(shared.NewID(), tid, "ci", "hash", "prefix")
	k.SetScopes(scopes)
	if revoked {
		if err := k.Revoke(shared.NewID()); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

// A queued upload sent with an API key is re-checked against the key when it
// is imported: a revoked, expired or deleted key is refused, and the right to
// approve is kept only while the key's scopes still hold it.
func TestCurrentCaller_ChecksTheAPIKeyNow(t *testing.T) {
	ctx := context.Background()
	tid := shared.NewID()
	caller := Caller{APIKey: true, APIKeyID: shared.NewID().String()}
	expired := keyWith(t, tid, false, "findings:approve")
	past := time.Now().Add(-time.Hour)
	expired.SetExpiresAt(&past)
	cases := []struct {
		name        string
		keys        fakeKeys
		canApprove  bool
		wantErr     error
		wantApprove bool
	}{
		{"revoked", fakeKeys{key: keyWith(t, tid, true, "findings:approve")}, true, shared.ErrNotFound, false},
		{"expired", fakeKeys{key: expired}, true, shared.ErrNotFound, false},
		{"deleted", fakeKeys{err: apikey.ErrAPIKeyNotFound}, true, shared.ErrNotFound, false},
		{"scope removed", fakeKeys{key: keyWith(t, tid, false, "findings:read")}, true, nil, false},
		{"scope kept", fakeKeys{key: keyWith(t, tid, false, "findings:approve")}, true, nil, true},
		{"never widened", fakeKeys{key: keyWith(t, tid, false, "findings:approve")}, false, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{}
			s.SetRights(tc.keys, nil)
			env := Envelope{Caller: caller, CanApprove: tc.canApprove}
			err := s.currentCaller(ctx, tid, &env)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || env.CanApprove != tc.wantApprove {
				t.Fatalf("err=%v canApprove=%v, want %v", err, env.CanApprove, tc.wantApprove)
			}
		})
	}

	// A lookup failure is retried, never read as revoked or as allowed.
	s := &Service{}
	s.SetRights(fakeKeys{err: errors.New("db down")}, nil)
	env := Envelope{Caller: caller, CanApprove: true}
	if err := s.currentCaller(ctx, tid, &env); err == nil || errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("lookup error = %v", err)
	}
}

// A person's upload keeps findings:approve only while the person still holds
// it (an administrator always does).
func TestCurrentCaller_ChecksApproveNow(t *testing.T) {
	ctx := context.Background()
	tid, uid := shared.NewID(), shared.NewID()
	member := func(role tenant.Role) fakeMembers {
		m, err := tenant.NewMembership(uid, tid, role, nil)
		if err != nil {
			t.Fatal(err)
		}
		return fakeMembers{m: m}
	}
	cases := []struct {
		name    string
		members fakeMembers
		perms   fakePerms
		want    bool
		wantErr bool
	}{
		{"permission removed", member(tenant.RoleMember), fakePerms{held: false}, false, false},
		{"permission kept", member(tenant.RoleMember), fakePerms{held: true}, true, false},
		{"administrator", member(tenant.RoleAdmin), fakePerms{held: false}, true, false},
		{"lookup error", member(tenant.RoleMember), fakePerms{err: errors.New("db down")}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{}
			s.SetMembers(tc.members)
			s.SetRights(nil, tc.perms)
			env := Envelope{Caller: Caller{UserID: uid.String()}, CanApprove: true}
			err := s.currentCaller(ctx, tid, &env)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if err == nil && env.CanApprove != tc.want {
				t.Fatalf("canApprove = %v, want %v", env.CanApprove, tc.want)
			}
		})
	}
	// A recorded "cannot approve" is never widened by a held permission.
	s := &Service{}
	s.SetMembers(member(tenant.RoleOwner))
	s.SetRights(nil, fakePerms{held: true})
	env := Envelope{Caller: Caller{UserID: uid.String()}}
	if err := s.currentCaller(ctx, tid, &env); err != nil || env.CanApprove {
		t.Fatalf("widened: %v %v", err, env.CanApprove)
	}
}

type recentFails struct{ Queue }

func (recentFails) Recent(context.Context, shared.ID, ingestjob.Kind, string, []byte, time.Duration) (*ingestjob.Job, error) {
	return nil, errors.New("connection reset")
}
func (recentFails) Discard(context.Context, shared.ID, shared.ID) {}

type stubReceipts struct{ ReceiptStore }

// An unkeyed upload whose retry lookup fails is answered as unavailable
// (503), not as a server fault, and stores nothing.
func TestCommitUpload_RecentLookupErrorIsUnavailable(t *testing.T) {
	s := &Service{logger: logger.NewNop(), queue: recentFails{}, receipts: stubReceipts{},
		resolveScope: func(context.Context, shared.ID, Caller) (ingest.ActorScope, ingest.ActorScope, error) {
			return nil, nil, nil
		}}
	_, err := s.CommitUpload(context.Background(), shared.NewID(), nil, shared.NewID(), "user:x", []byte("d"), false, "a.json", Envelope{})
	if !errors.Is(err, ErrQueueUnavailable) {
		t.Fatalf("err = %v, want ErrQueueUnavailable", err)
	}
}
