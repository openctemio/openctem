package pagemon

import (
	"context"
	"errors"
	"net/url"
	"strings"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/pagemon"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Reasons stored on held watches (English only: shown as a code).
const (
	reasonNoCapability = "no sensor can fetch web content yet"
	reasonDispatch     = "the fetch could not be started"
)

// Run dispatches the due watches of every tenant that skip does not leave
// out (the Attack surface module off) and that has automatic coverage on.
// It returns how many URLs were handed to runs.
func (s *Service) Run(ctx context.Context, skip func(shared.ID) bool) (int, error) {
	if s.dispatch == nil {
		return 0, nil
	}
	now := s.now()
	tenants, err := s.store.TenantsWithDueWatches(ctx, now)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		if skip != nil && skip(t) {
			continue
		}
		if s.coverage != nil {
			on, err := s.coverage.CoverageEnabled(ctx, t)
			if err != nil || !on {
				continue // automatic active traffic is off for this tenant
			}
		}
		n, err := s.dispatchTenant(ctx, t)
		if err != nil {
			s.log.Warn("page monitoring: dispatch failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
			continue
		}
		total += n
	}
	return total, nil
}

func (s *Service) dispatchTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	now := s.now()
	due, err := s.store.DueWatches(ctx, tenantID, now, dispatchPerTenant*2)
	if err != nil {
		return 0, err
	}
	due = capPerHost(due, dispatchPerHost, dispatchPerTenant)
	if len(due) == 0 {
		return 0, nil
	}
	byURL := make(map[string]shared.ID, len(due))
	targets := make([]string, 0, len(due))
	for _, w := range due {
		byURL[strings.ToLower(w.URL)] = w.ID
		targets = append(targets, w.URL)
	}
	if !s.known() {
		return 0, s.store.MarkHeld(ctx, tenantID, reasonsFor(due, reasonNoCapability), pagemon.StateWaiting, now.Add(pagemon.WaitingRetry))
	}
	res, err := s.dispatch.StartCoverage(ctx, scanapp.CoverageInput{TenantID: tenantID, Capability: pagemon.Capability, Targets: targets})
	if errors.Is(err, scanapp.ErrCoverageBusy) {
		return 0, nil // the previous run is still active; next pass
	}
	if err != nil {
		s.log.Info("page monitoring: fetch not started", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return 0, s.store.MarkHeld(ctx, tenantID, reasonsFor(due, reasonDispatch), pagemon.StateWaiting, now.Add(pagemon.WaitingRetry))
	}
	refused := map[shared.ID]string{}
	for _, r := range res.Refused {
		if id, ok := byURL[strings.ToLower(strings.TrimSpace(r.Target))]; ok {
			refused[id] = "refused by the scan gate: " + r.Code
		}
	}
	if len(refused) > 0 {
		if err := s.store.MarkHeld(ctx, tenantID, refused, pagemon.StateBlocked, now.Add(pagemon.BlockedRetry)); err != nil {
			return 0, err
		}
	}
	kept := make([]shared.ID, 0, len(res.Kept))
	for _, k := range res.Kept {
		if id, ok := byURL[strings.ToLower(strings.TrimSpace(k))]; ok {
			kept = append(kept, id)
		}
	}
	if len(kept) == 0 {
		return 0, nil
	}
	return len(kept), s.store.MarkDispatched(ctx, tenantID, kept, res.RunID, now)
}

func reasonsFor(ws []pagemon.Watch, reason string) map[shared.ID]string {
	out := make(map[shared.ID]string, len(ws))
	for _, w := range ws {
		out[w.ID] = reason
	}
	return out
}

// capPerHost keeps at most perHost watches per host and total overall, in
// the given (due) order: the rate limit per target.
func capPerHost(ws []pagemon.Watch, perHost, total int) []pagemon.Watch {
	counts := map[string]int{}
	out := make([]pagemon.Watch, 0, min(len(ws), total))
	for _, w := range ws {
		u, err := url.Parse(w.URL)
		if err != nil {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if counts[h] >= perHost {
			continue
		}
		counts[h]++
		out = append(out, w)
		if len(out) == total {
			break
		}
	}
	return out
}
