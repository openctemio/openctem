package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Outbound webhook signing secret and redelivery
// (docs/rfcs/RFC-122-outbound-webhooks.md).

// DeliveryRedeliverer queues an archived notification event again for one
// integration (internal/app/outbox.Service).
type DeliveryRedeliverer interface {
	Redeliver(ctx context.Context, tenantID, integrationID, deliveryID shared.ID) (*outboxdom.Outbox, error)
}

// SetDeliveryRedeliverer wires redelivery; without it the route answers 404.
func (h *IntegrationHandler) SetDeliveryRedeliverer(r DeliveryRedeliverer) { h.redeliverer = r }

// RedeliveryResponse names the queued redelivery.
type RedeliveryResponse struct {
	// DeliveryID is the archived event sent again.
	DeliveryID string `json:"delivery_id"`
	// RedeliveryID is the new delivery; it appears in the delivery history
	// once processed, with metadata.redelivery_of = delivery_id.
	RedeliveryID string `json:"redelivery_id"`
	Status       string `json:"status"`
}

// WebhookSigningSecretResponse carries a new signing secret, shown only in
// the rotation response.
type WebhookSigningSecretResponse struct {
	Secret             string     `json:"secret"`
	RotatedAt          time.Time  `json:"rotated_at"`
	PreviousValidUntil *time.Time `json:"previous_valid_until,omitempty"`
}

// GetWebhookSigning handles GET /api/v1/integrations/{id}/signing-secret.
// @Summary      Signing secret status of a webhook integration
// @Description  Whether the generic webhook integration signs its deliveries, when the secret was rotated and until when the previous one still signs. The secret is never returned.
// @Tags         Integrations
// @Produce      json
// @Param        id   path      string  true  "Integration ID"  format(uuid)
// @Success      200  {object}  integration.SigningSecretStatus
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      403  {object}  map[string]string  "Forbidden"
// @Failure      404  {object}  map[string]string  "Not found (no such webhook integration in this organization)"
// @Security     BearerAuth
// @Router       /integrations/{id}/signing-secret [get]
func (h *IntegrationHandler) GetWebhookSigning(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.webhookIntegrationID(w, r)
	if !ok {
		return
	}
	st, err := h.service.WebhookSigningStatus(r.Context(), tid, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

// RotateWebhookSigningSecret handles POST /api/v1/integrations/{id}/signing-secret/rotate.
// @Summary      Rotate the signing secret of a webhook integration
// @Description  Generates a new whsec_ secret and returns it in this response only. The replaced secret keeps signing for 24 hours (deliveries carry both signatures). The first rotation creates the secret. Requires step-up.
// @Tags         Integrations
// @Produce      json
// @Param        id   path      string  true  "Integration ID"  format(uuid)
// @Success      200  {object}  WebhookSigningSecretResponse
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      403  {object}  map[string]string  "Forbidden (permission or step-up)"
// @Failure      404  {object}  map[string]string  "Not found (no such webhook integration in this organization)"
// @Security     BearerAuth
// @Router       /integrations/{id}/signing-secret/rotate [post]
func (h *IntegrationHandler) RotateWebhookSigningSecret(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.webhookIntegrationID(w, r)
	if !ok {
		return
	}
	rotated, err := h.service.RotateWebhookSigningSecret(r.Context(), tid, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	meta := map[string]any{"provider": string(integration.ProviderWebhook), "secret": "signing", "overlap": rotated.PreviousValidUntil != nil}
	h.auditIntegration(r, auditdom.ActionIntegrationWebhookSecretRotated, id.String(), "Webhook signing secret", nil, nil,
		auditdom.SeverityCritical, "Outbound webhook signing secret rotated", meta)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(WebhookSigningSecretResponse{
		Secret:             rotated.Secret,
		RotatedAt:          rotated.RotatedAt,
		PreviousValidUntil: rotated.PreviousValidUntil,
	})
}

// RedeliverNotification handles POST /api/v1/integrations/{id}/deliveries/{delivery_id}/redeliver.
// @Summary      Send a delivery again
// @Description  Queues the archived event {delivery_id} again for this integration only. The event must be this organization's and must have gone (or failed to go) to this integration. The redelivery keeps the event's idempotency key (webhook-id), is signed with the current secret and is retried like any delivery.
// @Tags         Integrations
// @Produce      json
// @Param        id           path  string  true  "Integration ID"  format(uuid)
// @Param        delivery_id  path  string  true  "Delivery (notification event) ID"  format(uuid)
// @Success      202  {object}  RedeliveryResponse
// @Failure      400  {object}  map[string]string  "The integration is not connected"
// @Failure      401  {object}  map[string]string  "Unauthorized"
// @Failure      403  {object}  map[string]string  "Forbidden"
// @Failure      404  {object}  map[string]string  "Not found (no such delivery of this integration in this organization)"
// @Failure      429  {object}  map[string]string  "Too many requests"
// @Security     BearerAuth
// @Router       /integrations/{id}/deliveries/{delivery_id}/redeliver [post]
func (h *IntegrationHandler) RedeliverNotification(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.webhookIntegrationID(w, r)
	if !ok {
		return
	}
	deliveryID, err := shared.IDFromString(r.PathValue("delivery_id"))
	if err != nil || h.redeliverer == nil {
		apierror.NotFound("Delivery").WriteJSON(w)
		return
	}
	entry, err := h.redeliverer.Redeliver(r.Context(), tid, id, deliveryID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.auditIntegration(r, auditdom.ActionIntegrationDeliveryRedelivered, id.String(), "Notification redelivery", nil, nil,
		auditdom.SeverityMedium, "Notification delivery sent again",
		map[string]any{"delivery_id": deliveryID.String(), "redelivery_id": entry.ID().String(), "event_type": entry.EventType()})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(RedeliveryResponse{
		DeliveryID:   deliveryID.String(),
		RedeliveryID: entry.ID().String(),
		Status:       "queued",
	})
}
