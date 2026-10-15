package redis

import (
	"context"
	"time"
)

// WebhookDeliveryStore remembers the delivery ids of verified inbound
// webhooks across API replicas (SET NX with a TTL), so a captured signed
// delivery cannot be replayed inside the window.
type WebhookDeliveryStore struct {
	client *Client
}

// NewWebhookDeliveryStore returns a delivery store on client.
func NewWebhookDeliveryStore(client *Client) *WebhookDeliveryStore {
	return &WebhookDeliveryStore{client: client}
}

// FirstDelivery records key and reports whether it was new. The caller puts
// the provider, the organization and the delivery id in key.
func (s *WebhookDeliveryStore) FirstDelivery(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return s.client.SetNX(ctx, "webhook:delivery:"+key, "1", ttl)
}

// ReleaseDelivery forgets a delivery key (FirstDelivery is true for it again),
// so a delivery whose processing failed is processed on the sender's retry.
func (s *WebhookDeliveryStore) ReleaseDelivery(ctx context.Context, key string) error {
	return s.client.Del(ctx, "webhook:delivery:"+key)
}
