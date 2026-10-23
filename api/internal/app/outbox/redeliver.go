package outbox

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MetaRedeliveryOf names, in a redelivery's metadata, the archived event it
// sends again. The redelivery keeps that event's idempotency key.
const MetaRedeliveryOf = "redelivery_of"

// ErrDeliveryNotFound answers every redelivery that cannot name a delivery
// of this tenant: unknown event, another tenant's event, or an event that
// never went to this integration. One answer, so the route is no oracle.
var ErrDeliveryNotFound = fmt.Errorf("%w: delivery not found", shared.ErrNotFound)

// ErrRedeliveryChannelUnavailable: the integration is not connected (or not
// a notification channel), so a redelivery would only fail.
var ErrRedeliveryChannelUnavailable = fmt.Errorf("%w: the integration is not connected", shared.ErrValidation)

// Redeliver sends an archived event again to one integration it was
// delivered (or failed to be delivered) to. It queues a new outbox entry for
// that channel only: the entry goes through the normal pass, so the
// private-program routing is checked again and the delivery is signed,
// retried and archived like any other. The event must be the tenant's and
// must name the integration in its send results: a redelivery never sends
// an event to a channel that was not one of its channels.
func (s *Service) Redeliver(ctx context.Context, tenantID, integrationID, deliveryID shared.ID) (*outboxdom.Outbox, error) {
	ev, err := s.eventRepo.GetByTenantAndID(ctx, tenantID, deliveryID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, ErrDeliveryNotFound
		}
		return nil, fmt.Errorf("load delivery: %w", err)
	}
	var sent *outboxdom.SendResult
	for _, r := range ev.SendResults() {
		if r.IntegrationID == integrationID.String() {
			sent = &r
			break
		}
	}
	if sent == nil {
		return nil, ErrDeliveryNotFound
	}

	intg, err := s.notificationRepo.GetIntegrationWithNotification(ctx, integrationID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, ErrDeliveryNotFound
		}
		return nil, fmt.Errorf("load integration: %w", err)
	}
	if intg == nil || intg.Integration == nil || intg.Integration.TenantID() != tenantID {
		return nil, ErrDeliveryNotFound
	}
	if intg.Integration.Status() != integration.StatusConnected {
		return nil, ErrRedeliveryChannelUnavailable
	}

	meta := make(map[string]any, len(ev.Metadata())+1)
	maps.Copy(meta, ev.Metadata())
	orig := ev.ID().String()
	if prev, ok := ev.Metadata()[MetaRedeliveryOf].(string); ok && prev != "" {
		// A redelivery of a redelivery still names the first event.
		orig = prev
	}
	meta[MetaRedeliveryOf] = orig

	entry := outboxdom.NewOutbox(outboxdom.OutboxParams{
		TenantID:      tenantID,
		EventType:     ev.EventType(),
		AggregateType: ev.AggregateType(),
		AggregateID:   ev.AggregateID(),
		Title:         ev.Title(),
		Body:          ev.Body(),
		Severity:      ev.Severity(),
		URL:           ev.URL(),
		Metadata:      meta,
	})
	entry.SetDeliveries([]outboxdom.ChannelDelivery{
		outboxdom.NewChannelDelivery(integrationID.String(), intg.Integration.Name(), intg.Integration.Provider().String()),
	})
	if err := s.outboxRepo.Create(ctx, entry); err != nil {
		return nil, fmt.Errorf("queue redelivery: %w", err)
	}
	return entry, nil
}
