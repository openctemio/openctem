package apikey

// Expiry notice (docs/architecture/api-keys.md, "Maximum lifetime"): the
// person who minted a key is told, in-app, once, a week before it expires,
// so an integration is rotated before it stops.

import (
	"context"
	"fmt"
	"time"

	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ExpiryNoticeLead is how long before expiry the holder is told.
const ExpiryNoticeLead = 7 * 24 * time.Hour

// InAppNotifier sends an in-app notice to one user.
type InAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// SetExpiryNotifier wires the in-app notice of keys that expire soon.
func (s *Service) SetExpiryNotifier(n InAppNotifier) { s.expiryNotifier = n }

// NotifyExpiring tells the holder of every active key that expires within
// ExpiryNoticeLead, once (the mark is a compare-and-swap, so two replicas
// never both send). The recipient is the person who minted the key (for a
// service account key, its creator), else the key's user. It answers how many
// notices were sent.
func (s *Service) NotifyExpiring(ctx context.Context, now time.Time, batch int) (int, error) {
	repo, ok := s.repo.(apikeydom.ExpiryNoticeRepository)
	if !ok || s.expiryNotifier == nil {
		return 0, nil
	}
	keys, err := repo.ListExpiringUnnoticed(ctx, now.Add(ExpiryNoticeLead), batch)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, k := range keys {
		to := k.CreatedBy
		if to == nil {
			to = k.UserID
		}
		if to == nil {
			continue
		}
		marked, err := repo.MarkExpiryNoticed(ctx, k.TenantID, k.ID)
		if err != nil {
			return sent, err
		}
		if !marked {
			continue
		}
		days := int(k.ExpiresAt.Sub(now).Hours()/24) + 1
		if err := s.expiryNotifier.Notify(ctx, notificationdom.NotificationParams{
			TenantID:         k.TenantID,
			Audience:         notificationdom.AudienceUser,
			AudienceID:       to,
			NotificationType: notificationdom.TypeSystemAlert,
			Title:            "API key expires soon",
			Body: fmt.Sprintf("The API key %q (%s…) expires on %s, in about %d day(s). Create a new key and switch to it before then.",
				k.Name, k.Prefix, k.ExpiresAt.UTC().Format("2006-01-02"), days),
			Severity:     notificationdom.SeverityMedium,
			ResourceType: "api_key",
			ResourceID:   &k.ID,
			URL:          "/settings/api-keys",
		}); err != nil {
			s.logger.Warn("api key expiry notice", "key_id", k.ID.String(), "error", logger.SanitizeError(err))
			continue
		}
		sent++
	}
	return sent, nil
}
