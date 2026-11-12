package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/serviceaccount"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ServiceKeyCreatorStore lists who minted live service-account keys and
// revokes keys (*postgres.ServiceAccountRepository, *postgres.MemberLifecycleRepository).
type ServiceKeyCreatorStore interface {
	ListServiceKeyCreators(ctx context.Context) ([]serviceaccount.KeyCreator, error)
	RevokeKeysWithoutCreator(ctx context.Context, tenantID shared.ID) (int, error)
}

// ServiceKeyRevoker revokes the service-account keys one person minted.
type ServiceKeyRevoker interface {
	RevokeServiceAccountKeys(ctx context.Context, tenantID, userID shared.ID, revokedBy *shared.ID) (int, error)
}

// ServiceKeyCreatorGate is apikey.ServiceKeyGate's creator check.
type ServiceKeyCreatorGate interface {
	CreatorRefusal(ctx context.Context, tenantID shared.ID, createdBy *shared.ID) (string, error)
}

// ServiceKeyCreatorController marks service-account keys revoked once the
// person who minted them no longer holds service_accounts:manage in the
// tenant, so the access report shows them. The key-use check already refuses
// such a key on every request; this sweep only makes the state visible and
// covers changes that happen with no request in between (a team membership
// that ended by the clock). A lookup error skips that person until the next run.
type ServiceKeyCreatorController struct {
	store    ServiceKeyCreatorStore
	gate     ServiceKeyCreatorGate
	revoker  ServiceKeyRevoker
	interval time.Duration
	logger   *logger.Logger
}

// NewServiceKeyCreatorController creates the controller.
func NewServiceKeyCreatorController(store ServiceKeyCreatorStore, gate ServiceKeyCreatorGate, revoker ServiceKeyRevoker, interval time.Duration, log *logger.Logger) *ServiceKeyCreatorController {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &ServiceKeyCreatorController{store: store, gate: gate, revoker: revoker, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *ServiceKeyCreatorController) Name() string { return "service-key-creator" }

// Interval returns the reconciliation interval.
func (c *ServiceKeyCreatorController) Interval() time.Duration { return c.interval }

// Exclusive makes one replica run the sweep at a time.
func (c *ServiceKeyCreatorController) Exclusive() bool { return true }

// Reconcile revokes the keys of creators who no longer qualify and returns how many.
func (c *ServiceKeyCreatorController) Reconcile(ctx context.Context) (int, error) {
	creators, err := c.store.ListServiceKeyCreators(ctx)
	if err != nil {
		c.logger.Error("service key creator sweep: list failed", "error", err)
		return 0, err
	}
	revoked := 0
	for _, sc := range creators {
		if sc.UserID.IsZero() {
			n, err := c.store.RevokeKeysWithoutCreator(ctx, sc.TenantID)
			if err != nil {
				c.logger.Error("service key creator sweep: revoke failed", "tenant_id", sc.TenantID.String(), "error", err)
				continue
			}
			revoked += n
			continue
		}
		uid := sc.UserID
		reason, err := c.gate.CreatorRefusal(ctx, sc.TenantID, &uid)
		if err != nil || reason == "" {
			if err != nil {
				c.logger.Warn("service key creator sweep: check failed, skipped", "tenant_id", sc.TenantID.String(), "error", err)
			}
			continue
		}
		n, err := c.revoker.RevokeServiceAccountKeys(ctx, sc.TenantID, uid, nil)
		if err != nil {
			c.logger.Error("service key creator sweep: revoke failed", "tenant_id", sc.TenantID.String(), "error", err)
			continue
		}
		if n > 0 {
			c.logger.Warn("revoked service-account keys: creator no longer qualifies",
				"tenant_id", sc.TenantID.String(), "creator_id", uid.String(), "reason", reason, "count", n)
		}
		revoked += n
	}
	return revoked, nil
}
