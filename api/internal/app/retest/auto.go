package retest

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/internal/app/validation"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Auto-retest scheduling bounds (RFC-039 §6.3, §8.1).
const (
	// TickInterval is how often a tenant's auto-retest tick may fire. Each tick
	// queues what fits in the tenant's budget; the backlog drains over ticks.
	TickInterval = 5 * time.Minute
	// MaxQueuedPerTick bounds the auto retests queued in one scheduler pass
	// across all tenants (fair share between tenants on shared capacity).
	MaxQueuedPerTick = 100
	// maxTenantsPerTick bounds the tenants served in one pass; the rest are
	// served on the next pass, least recently served first.
	maxTenantsPerTick = 50
	// candidateOverfetch: candidates are listed with headroom because some are
	// skipped (per-asset cap, gate refusal) without consuming budget.
	candidateOverfetch = 3
)

// AutoStore is the persistence the auto-retest tick needs.
type AutoStore interface {
	ListDueAutoTenants(ctx context.Context, now time.Time, limit int) ([]retestdom.AutoTenant, error)
	ClaimTenantTick(ctx context.Context, tenantID shared.ID, seen *time.Time, next time.Time) (bool, error)
	ListAutoCandidates(ctx context.Context, tenantID shared.ID, retestedBefore, resolvedSince time.Time, limit int) ([]shared.ID, error)
	CountCreatedSince(ctx context.Context, tenantID shared.ID, trigger retestdom.Trigger, since time.Time) (int, error)
	CountPending(ctx context.Context, tenantID shared.ID, trigger retestdom.Trigger) (int, error)
}

// TickResult reports one scheduler pass.
type TickResult struct {
	TenantsClaimed int // ticks this caller won (and served)
	Queued         int // auto retests queued
}

// RunAutoTick serves every tenant whose auto-retest tick is due. A tick is
// claimed (compare-and-set on the tenant's cursor) before anything is queued,
// so with several API replicas each tick is served by exactly one of them.
func (s *Service) RunAutoTick(ctx context.Context, auto AutoStore) (TickResult, error) {
	var res TickResult
	now := s.now().UTC()
	tenants, err := auto.ListDueAutoTenants(ctx, now, maxTenantsPerTick)
	if err != nil {
		return res, err
	}
	globalLeft := MaxQueuedPerTick
	for _, t := range tenants {
		if globalLeft <= 0 {
			break
		}
		won, err := auto.ClaimTenantTick(ctx, t.TenantID, t.NextRunAt, now.Add(TickInterval))
		if err != nil {
			s.logger.Warn("auto-retest claim failed", "tenant_id", t.TenantID.String(), "error", err)
			continue
		}
		if !won {
			continue // another replica serves this tick
		}
		res.TenantsClaimed++
		n := s.serveTenant(ctx, auto, t, now, globalLeft)
		res.Queued += n
		globalLeft -= n
	}
	return res, nil
}

// serveTenant queues up to the tenant's remaining daily budget, in-flight room
// and the pass's global allowance. Returns how many it queued.
func (s *Service) serveTenant(ctx context.Context, auto AutoStore, t retestdom.AutoTenant, now time.Time, globalLeft int) int {
	settings := tenant.RetestSettings{IntervalHours: t.IntervalHours, DailyCap: t.DailyCap}
	created, err := auto.CountCreatedSince(ctx, t.TenantID, retestdom.TriggerAuto, now.Add(-24*time.Hour))
	if err != nil {
		s.logger.Warn("auto-retest budget lookup failed", "tenant_id", t.TenantID.String(), "error", err)
		return 0
	}
	pending, err := auto.CountPending(ctx, t.TenantID, retestdom.TriggerAuto)
	if err != nil {
		s.logger.Warn("auto-retest in-flight lookup failed", "tenant_id", t.TenantID.String(), "error", err)
		return 0
	}
	want := min(settings.EffectiveDailyCap()-created, MaxPendingAuto-pending, globalLeft)
	if want <= 0 {
		return 0
	}
	interval := time.Duration(settings.EffectiveIntervalHours()) * time.Hour
	candidates, err := auto.ListAutoCandidates(ctx, t.TenantID, now.Add(-interval), now.Add(-ResolvedLookback), want*candidateOverfetch)
	if err != nil {
		s.logger.Warn("auto-retest candidate lookup failed", "tenant_id", t.TenantID.String(), "error", err)
		return 0
	}
	queued := 0
	for _, fid := range candidates {
		if queued >= want {
			break
		}
		_, err := s.Request(ctx, RequestInput{TenantID: t.TenantID, FindingID: fid, Trigger: retestdom.TriggerAuto})
		switch {
		case err == nil:
			queued++
		case errors.Is(err, retestdom.ErrNoSensor):
			// Nothing can run for this tenant now; try again next tick.
			return queued
		case errors.Is(err, validation.ErrTargetRefused):
			s.logger.Info("auto-retest skipped: the active-probe gate refused the target",
				"tenant_id", t.TenantID.String(), "finding_id", fid.String(), "reason", err.Error())
			continue
		case errors.Is(err, retestdom.ErrNotEligible), errors.Is(err, retestdom.ErrInFlight),
			errors.Is(err, retestdom.ErrRateLimited), errors.Is(err, shared.ErrNotFound):
			continue
		default:
			s.logger.Warn("auto-retest request failed", "tenant_id", t.TenantID.String(),
				"finding_id", fid.String(), "error", err)
		}
	}
	if queued > 0 {
		s.logger.Info("auto-retest tick served", "tenant_id", t.TenantID.String(), "queued", queued)
	}
	return queued
}

// sweepBatch bounds the pending retests settled in one pass.
const sweepBatch = 200

// Tick is one scheduler pass: settle stale retests, then serve due auto-retest
// ticks (when an AutoStore is wired). Returns the number of retests settled
// plus queued, for the controller's metrics.
func (s *Service) Tick(ctx context.Context, auto AutoStore) (int, error) {
	settled, err := s.Sweep(ctx, sweepBatch)
	if err != nil {
		s.logger.Warn("retest sweep failed", "error", err)
	}
	if auto == nil {
		return settled, err
	}
	res, autoErr := s.RunAutoTick(ctx, auto)
	if autoErr != nil {
		return settled + res.Queued, autoErr
	}
	return settled + res.Queued, err
}
