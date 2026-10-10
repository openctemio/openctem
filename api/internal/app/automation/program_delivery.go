package automation

// Automations are organization-wide: their actions post to webhooks,
// notification channels and ticket trackers any administrator configured.
// An event about an asset only private programs list (and not opted in to
// organization channels by an owner) starts no automation, so it cannot be
// forwarded outside the program. Design:
// docs/rfcs/RFC-065-bug-bounty-programs.md §15.4.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetDeliveryResolver wires the private program routing rule. Without it
// every event starts automations as before.
func (d *WorkflowEventDispatcher) SetDeliveryResolver(r bountyprogram.DeliveryResolver) {
	d.delivery = r
}

// restrictedAssets returns the restricted ids among assetIDs. ok is false
// when the decision is unknown: the caller then starts nothing (fail
// closed).
func (d *WorkflowEventDispatcher) restrictedAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]bool, bool) {
	if d.delivery == nil || len(assetIDs) == 0 {
		return nil, true
	}
	got, err := d.delivery.RestrictedAssets(ctx, tenantID, assetIDs)
	if err != nil {
		d.logger.Error("automation not started: private program check failed", "tenant_id", tenantID, "error", err)
		return nil, false
	}
	return got, true
}

// restrictedSubject reports whether an event about subject must start no
// automation (restricted, or the decision is unknown).
func (d *WorkflowEventDispatcher) restrictedSubject(ctx context.Context, tenantID shared.ID, subject bountyprogram.DeliverySubject) bool {
	if d.delivery == nil || subject.Empty() {
		return false
	}
	got, err := d.delivery.Resolve(ctx, tenantID, subject)
	if err != nil {
		d.logger.Error("automation not started: private program check failed", "tenant_id", tenantID, "error", err)
		return true
	}
	return got.IsRestricted()
}
