package redis

import (
	"context"
	"time"
)

// SensorNonceStore remembers the nonces of signed sensor requests (RFC-052
// §4.3) across API replicas: SET NX with the signature window as TTL.
type SensorNonceStore struct {
	client *Client
}

// NewSensorNonceStore returns a nonce store on client.
func NewSensorNonceStore(client *Client) *SensorNonceStore {
	return &SensorNonceStore{client: client}
}

// Use records nonce for keyID and reports whether it was new. The key is
// global, not per tenant: keyIDs (key thumbprints) are unique platform-wide.
func (s *SensorNonceStore) Use(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error) {
	return s.client.SetNX(ctx, "sensorsig:nonce:"+keyID+":"+nonce, "1", ttl)
}
