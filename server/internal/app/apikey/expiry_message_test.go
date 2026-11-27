package apikey

import (
	"context"
	"testing"
	"time"

	apikeydom "github.com/openctemio/openctem/server/pkg/domain/apikey"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type expiryRepo struct {
	apikeydom.Repository
	keys []apikeydom.ExpiringKey
}

func (r expiryRepo) ListExpiringUnnoticed(context.Context, time.Time, int) ([]apikeydom.ExpiringKey, error) {
	return r.keys, nil
}
func (r expiryRepo) MarkExpiryNoticed(context.Context, apikeydom.ID, apikeydom.ID) (bool, error) {
	return true, nil
}

type expiryNotifier struct {
	got []notificationdom.NotificationParams
}

func (n *expiryNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.got = append(n.got, p)
	return nil
}

func TestNotifyExpiring_MessageCode(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	uid := shared.NewID()
	rec := &expiryNotifier{}
	s := &Service{
		repo: expiryRepo{keys: []apikeydom.ExpiringKey{{
			ID: shared.NewID(), TenantID: shared.NewID(), UserID: &uid, Name: "ci key", Prefix: "oc_ab",
			ExpiresAt: now.Add(48 * time.Hour),
		}}},
		expiryNotifier: rec, logger: logger.NewNop(),
	}
	if n, err := s.NotifyExpiring(context.Background(), now, 10); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	m := rec.got[0].Message
	if m == nil || m.Code != "api_key.expiring" || m.Params["key_name"] != "ci key" || m.Params["prefix"] != "oc_ab" ||
		m.Params["expires_at"] != "2026-12-03T00:00:00Z" || m.Params["days"] != 3 {
		t.Fatalf("message = %+v", m)
	}
}
