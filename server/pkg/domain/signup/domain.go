package signup

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// DomainPolicySource answers the sign-up policy of the organization that
// claims an email address's domain (domainverify.Service).
type DomainPolicySource interface {
	SignupPolicyForEmail(ctx context.Context, email string) (verifieddomain.EmailPolicy, bool, error)
}

// DomainFacts are the parts of an Identity that come from the address's
// domain claim.
type DomainFacts struct {
	Joinable          bool
	SSORequired       bool
	WorkspacesBlocked bool
}

// FactsForEmail reads the domain facts of email. A nil source has no facts.
// An error is returned as is: callers refuse (fail closed), since a claimed
// domain's sso_required or block cannot be checked.
func FactsForEmail(ctx context.Context, src DomainPolicySource, email string) (DomainFacts, error) {
	if src == nil {
		return DomainFacts{}, nil
	}
	ep, ok, err := src.SignupPolicyForEmail(ctx, email)
	if err != nil || !ok {
		return DomainFacts{}, err
	}
	return DomainFacts{
		Joinable:          ep.Joinable(),
		SSORequired:       ep.Policy.SSORequired,
		WorkspacesBlocked: ep.Policy.BlockNewWorkspaces,
	}, nil
}

// Apply copies the facts into id.
func (f DomainFacts) Apply(id Identity) Identity {
	id.DomainJoinable, id.SSORequired, id.WorkspacesBlocked = f.Joinable, f.SSORequired, f.WorkspacesBlocked
	return id
}
