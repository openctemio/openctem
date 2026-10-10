package bountyprogram

// Where events about a program's private assets may be delivered
// (docs/rfcs/RFC-065-bug-bounty-programs.md §15.4).
//
// - Program channels: a member (or owner) who may see the program's
//   details attaches a notification integration of the organization. It
//   then also receives events about the program's private assets, with the
//   program's name in them. Detaching narrows and needs membership only.
// - Organization channels: only an owner may let a private program's events
//   reach every organization-wide integration, with a reason; the route asks
//   for a recent re-authentication and the change is audited.

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Reason bounds for turning organization channels on.
const (
	minOptInReason = 10
	maxOptInReason = 500
)

// DeliverySettings is a program's delivery configuration.
type DeliverySettings struct {
	OrgChannels bool
	Channels    []bp.Channel
}

// SetDeliveryStore wires the delivery settings store. Without it the
// delivery endpoints answer not found.
func (s *Service) SetDeliveryStore(st bp.DeliveryStore) { s.delivery = st }

func (s *Service) deliveryStore() (bp.DeliveryStore, error) {
	if s.delivery == nil {
		return nil, errNotFound
	}
	return s.delivery, nil
}

// Delivery returns the program's delivery settings: members and owners who
// accepted a private program's current terms.
func (s *Service) Delivery(ctx context.Context, tenantID, actor, id shared.ID) (*bp.Program, DeliverySettings, error) {
	st, err := s.deliveryStore()
	if err != nil {
		return nil, DeliverySettings{}, err
	}
	p, err := s.loadAttested(ctx, tenantID, actor, id)
	if err != nil {
		return nil, DeliverySettings{}, err
	}
	on, err := st.OrgChannels(ctx, tenantID, id)
	if err != nil {
		return nil, DeliverySettings{}, err
	}
	ch, err := st.Channels(ctx, tenantID, id)
	if err != nil {
		return nil, DeliverySettings{}, err
	}
	return p, DeliverySettings{OrgChannels: on, Channels: ch}, nil
}

// AttachChannel attaches a notification integration of the tenant to the
// program. Widening: the caller must have accepted the current terms.
func (s *Service) AttachChannel(ctx context.Context, tenantID, actor, id, integrationID shared.ID) (*bp.Program, error) {
	st, err := s.deliveryStore()
	if err != nil {
		return nil, err
	}
	p, err := s.loadAttested(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	var by *shared.ID
	if !actor.IsZero() {
		by = &actor
	}
	if err := st.AttachChannel(ctx, tenantID, id, integrationID, by); err != nil {
		return nil, err
	}
	return p, nil
}

// DetachChannel detaches an integration from the program (narrowing:
// membership is enough).
func (s *Service) DetachChannel(ctx context.Context, tenantID, actor, id, integrationID shared.ID) (*bp.Program, error) {
	st, err := s.deliveryStore()
	if err != nil {
		return nil, err
	}
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, err
	}
	if err := st.DetachChannel(ctx, tenantID, id, integrationID); err != nil {
		return nil, err
	}
	return p, nil
}

// SetOrgChannels turns organization-wide delivery of a private program's
// events on or off. Owners only; turning it on needs a reason. A
// non-member who is not an owner gets not found (loadForCaller); a member
// who is not an owner gets forbidden.
func (s *Service) SetOrgChannels(ctx context.Context, tenantID, actor, id shared.ID, enabled bool, reason string) (*bp.Program, string, error) {
	st, err := s.deliveryStore()
	if err != nil {
		return nil, "", err
	}
	p, err := s.loadForCaller(ctx, tenantID, actor, id)
	if err != nil {
		return nil, "", err
	}
	if !s.ownerCaller(ctx) {
		return nil, "", fmt.Errorf("%w: only an owner may change organization channels", shared.ErrForbidden)
	}
	if !p.IsPrivate() {
		return nil, "", fmt.Errorf("%w: only a private program restricts its channels", shared.ErrValidation)
	}
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); enabled && (n < minOptInReason || n > maxOptInReason) {
		return nil, "", fmt.Errorf("%w: reason must be %d to %d characters", shared.ErrValidation, minOptInReason, maxOptInReason)
	}
	if utf8.RuneCountInString(reason) > maxOptInReason {
		return nil, "", fmt.Errorf("%w: reason must be at most %d characters", shared.ErrValidation, maxOptInReason)
	}
	if err := st.SetOrgChannels(ctx, tenantID, id, enabled); err != nil {
		return nil, "", err
	}
	return p, reason, nil
}

// ReadablePrograms returns which of the private programs (ids) the caller
// may read the names of in delivery telemetry such as the notification
// outbox: every one for an owner, otherwise the programs the caller is a
// member of. Anything else is scrubbed by the caller.
func (s *Service) ReadablePrograms(ctx context.Context, tenantID, actor shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	out := make(map[shared.ID]bool, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	if s.ownerCaller(ctx) {
		for _, id := range ids {
			out[id] = true
		}
		return out, nil
	}
	if actor.IsZero() {
		return out, nil
	}
	member, err := s.repo.MemberProgramIDs(ctx, tenantID, actor)
	if err != nil {
		return nil, err
	}
	want := make(map[shared.ID]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	for _, id := range member {
		if want[id] {
			out[id] = true
		}
	}
	return out, nil
}
