package redis

import (
	"context"
	"testing"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A delivery key is new once, then refused until its TTL expires; another
// key (another organization) is independent.
func TestWebhookDeliveryStore_FirstDeliveryOnce(t *testing.T) {
	rc, ok := testRedis(t).(*redislib.Client)
	if !ok {
		t.Skip("needs a single-node client")
	}
	store := NewWebhookDeliveryStore(&Client{client: rc, logger: logger.NewNop()})
	ctx := context.Background()
	key := "github:" + shared.NewID().String() + ":delivery-1"
	other := "github:" + shared.NewID().String() + ":delivery-1"
	t.Cleanup(func() { rc.Del(ctx, "webhook:delivery:"+key, "webhook:delivery:"+other) })

	if first, err := store.FirstDelivery(ctx, key, time.Minute); err != nil || !first {
		t.Fatalf("first delivery: (%v, %v), want (true, nil)", first, err)
	}
	if first, err := store.FirstDelivery(ctx, key, time.Minute); err != nil || first {
		t.Fatalf("replay: (%v, %v), want (false, nil)", first, err)
	}
	if first, err := store.FirstDelivery(ctx, other, time.Minute); err != nil || !first {
		t.Fatalf("other organization: (%v, %v), want (true, nil)", first, err)
	}
	if ttl := rc.TTL(ctx, "webhook:delivery:"+key).Val(); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("ttl = %v, want within the window", ttl)
	}
}
