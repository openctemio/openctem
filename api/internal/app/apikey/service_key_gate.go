package apikey

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Reasons a service-account key is refused because of the person who minted it.
// They go to the log (never the caller, who only sees "not found") so an
// operator can tell why a key stopped working.
const (
	ReasonCreatorMissing    = "creator_missing"
	ReasonCreatorInactive   = "creator_not_active_member"
	ReasonCreatorLostManage = "creator_lost_service_accounts_manage"
	ReasonCreatorLookup     = "creator_lookup_failed"
)

// ServiceAccountSource tells whether a user is a service account
// (postgres.ServiceAccountRepository).
type ServiceAccountSource interface {
	IsServiceAccount(ctx context.Context, userID shared.ID) (bool, error)
}

// ServiceKeyGate decides whether a service-account key may still be used: the
// person who minted it must still be an active member of the key's tenant and
// hold service_accounts:manage now. Held through direct roles or active,
// unexpired team bindings, whichever path changed.
type ServiceKeyGate interface {
	// Refusal returns "" when the key may be used, otherwise the reason. A
	// key of a person (not a service account) is always allowed here. An error
	// is a lookup failure: the caller refuses the key (fail closed).
	Refusal(ctx context.Context, tenantID, keyUserID shared.ID, createdBy *shared.ID) (string, error)
	// CreatorRefusal is the creator half of Refusal for a key already known
	// to be a service-account key (used by the sweep).
	CreatorRefusal(ctx context.Context, tenantID shared.ID, createdBy *shared.ID) (string, error)
}

// NewServiceKeyGate returns the ServiceKeyGate production wires. members and
// holder are the same resolvers every key request already uses; holder should
// read the role tables directly (not a cache), because a team membership ends
// by the clock, which no cache invalidation can signal.
func NewServiceKeyGate(accounts ServiceAccountSource, members MembershipChecker, holder HolderPermissions) ServiceKeyGate {
	return serviceKeyGate{accounts: accounts, members: members, holder: holder}
}

type serviceKeyGate struct {
	accounts ServiceAccountSource
	members  MembershipChecker
	holder   HolderPermissions
}

func (g serviceKeyGate) Refusal(ctx context.Context, tenantID, keyUserID shared.ID, createdBy *shared.ID) (string, error) {
	svc, err := g.accounts.IsServiceAccount(ctx, keyUserID)
	if err != nil {
		return ReasonCreatorLookup, err
	}
	if !svc {
		return "", nil
	}
	return g.CreatorRefusal(ctx, tenantID, createdBy)
}

func (g serviceKeyGate) CreatorRefusal(ctx context.Context, tenantID shared.ID, createdBy *shared.ID) (string, error) {
	if createdBy == nil || createdBy.IsZero() {
		return ReasonCreatorMissing, nil
	}
	active, err := g.members.IsActiveMember(ctx, tenantID, *createdBy)
	if err != nil {
		return ReasonCreatorLookup, err
	}
	if !active {
		return ReasonCreatorInactive, nil
	}
	all, perms, err := g.holder.HeldPermissions(ctx, tenantID, *createdBy)
	if err != nil {
		return ReasonCreatorLookup, err
	}
	if all {
		return "", nil
	}
	for _, p := range perms {
		if p == string(permission.ServiceAccountsManage) {
			return "", nil
		}
	}
	return ReasonCreatorLostManage, nil
}
