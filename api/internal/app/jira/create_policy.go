package jira

// The create policy in front of the finding → issue paths
// (docs/architecture/ticket-create-policy.md). It decides whether, never
// where or with what content: every create it lets through still runs the
// outbound gate, routing, the mapping profile and idempotency in
// CreateTicketFromFinding.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// holdRetryAfter is how long a failed create waits before the next try.
const holdRetryAfter = time.Hour

// IntegrationLookup reads one integration of a tenant.
type IntegrationLookup interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*integration.Integration, error)
}

// PolicyGate applies each integration's create policy and daily cap.
type PolicyGate struct {
	sync         *SyncService
	repo         ticketpolicy.Repository
	integrations IntegrationLookup
	modules      ModuleChecker
	logger       *logger.Logger
}

// ModuleChecker answers which modules a tenant has disabled.
type ModuleChecker interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// SetModuleChecker makes the release job skip tenants that disabled the
// integrations module (nil: run for every tenant).
func (g *PolicyGate) SetModuleChecker(m ModuleChecker) { g.modules = m }

// NewPolicyGate builds the gate.
func NewPolicyGate(sync *SyncService, repo ticketpolicy.Repository, integrations IntegrationLookup, log *logger.Logger) *PolicyGate {
	if log == nil {
		log = logger.NewNop()
	}
	return &PolicyGate{sync: sync, repo: repo, integrations: integrations, logger: log}
}

// ErrNotTicketingIntegration: the integration is not a Jira integration of
// the organization (answered as not found).
var ErrNotTicketingIntegration = fmt.Errorf("%w: ticketing integration not found", shared.ErrNotFound)

// ticketingIntegration checks the integration is one of the tenant's Jira
// integrations.
func (g *PolicyGate) ticketingIntegration(ctx context.Context, tenantID, integrationID shared.ID) error {
	if g.integrations == nil {
		return ErrNotTicketingIntegration
	}
	intg, err := g.integrations.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil || intg == nil || intg.TenantID() != tenantID || intg.Provider() != integration.ProviderJira {
		return ErrNotTicketingIntegration
	}
	return nil
}

// Policy returns the integration's policy and its counts.
func (g *PolicyGate) Policy(ctx context.Context, tenantID, integrationID shared.ID) (ticketpolicy.Policy, ticketpolicy.Stats, error) {
	if err := g.ticketingIntegration(ctx, tenantID, integrationID); err != nil {
		return ticketpolicy.Policy{}, ticketpolicy.Stats{}, err
	}
	p, err := g.repo.Get(ctx, tenantID, integrationID)
	if err != nil {
		return p, ticketpolicy.Stats{}, err
	}
	st, err := g.repo.Stats(ctx, tenantID, integrationID)
	return p, st, err
}

// SavePolicy validates and stores the integration's policy. It returns the
// policy before and after, for the audit record. Loosening it releases held
// findings through the background job, within the daily cap.
func (g *PolicyGate) SavePolicy(ctx context.Context, tenantID, integrationID shared.ID, p ticketpolicy.Policy, by *shared.ID) (before, after ticketpolicy.Policy, err error) {
	if err := g.ticketingIntegration(ctx, tenantID, integrationID); err != nil {
		return before, after, err
	}
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return before, after, err
	}
	if before, err = g.repo.Get(ctx, tenantID, integrationID); err != nil {
		return before, after, err
	}
	p.UpdatedBy = by
	after, err = g.repo.Save(ctx, tenantID, integrationID, p)
	return before, after, err
}

// Preview counts what a policy would let through (counts only).
func (g *PolicyGate) Preview(ctx context.Context, tenantID, integrationID shared.ID, p ticketpolicy.Policy) (ticketpolicy.Preview, error) {
	if err := g.ticketingIntegration(ctx, tenantID, integrationID); err != nil {
		return ticketpolicy.Preview{}, err
	}
	p = p.Normalize()
	if err := p.Validate(); err != nil {
		return ticketpolicy.Preview{}, err
	}
	return g.repo.Preview(ctx, tenantID, integrationID, p)
}

// BelowThreshold describes a finding the policy would hold back.
type BelowThreshold struct {
	IntegrationID shared.ID           `json:"integration_id"`
	Policy        ticketpolicy.Policy `json:"policy"`
}

// target resolves the integration and loads the finding. ok is false when
// the client cannot name its integration (a static test client): then no
// policy applies.
func (g *PolicyGate) target(ctx context.Context, in CreateTicketInput) (tenantID, integrationID shared.ID, f *vulnerability.Finding, ok bool, err error) {
	if tenantID, err = shared.IDFromString(in.TenantID); err != nil {
		return tenantID, integrationID, nil, false, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	findingID, err := shared.IDFromString(in.FindingID)
	if err != nil {
		return tenantID, integrationID, nil, false, fmt.Errorf("%w: invalid finding ID", shared.ErrValidation)
	}
	if v := in.IntegrationID; v != "" {
		if integrationID, err = shared.IDFromString(v); err != nil {
			return tenantID, integrationID, nil, false, fmt.Errorf("%w: invalid integration ID", shared.ErrValidation)
		}
	}
	client, err := g.sync.clientFor(ctx, tenantID, integrationID)
	if err != nil {
		return tenantID, integrationID, nil, false, err
	}
	ii, ok := client.(IssueIdentifier)
	if !ok {
		return tenantID, integrationID, nil, false, nil
	}
	integrationID = ii.IntegrationID()
	if f, err = g.sync.findingRepo.GetByID(ctx, tenantID, findingID); err != nil {
		return tenantID, integrationID, nil, false, fmt.Errorf("get finding: %w", err)
	}
	return tenantID, integrationID, f, true, nil
}

// AutoCreate is the automatic path (a workflow's create_ticket action). A
// finding below the policy, or over today's cap, is held and nothing is
// sent; held is then non-nil and err nil.
func (g *PolicyGate) AutoCreate(ctx context.Context, in CreateTicketInput) (*TicketInfo, *ticketpolicy.Hold, error) {
	in.Route = ticketing.RouteAutomation
	tenantID, integrationID, f, ok, err := g.target(ctx, in)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		info, err := g.sync.CreateTicketFromFinding(ctx, in)
		return info, nil, err
	}
	p, err := g.repo.Get(ctx, tenantID, integrationID)
	if err != nil {
		return nil, nil, err
	}
	hold := ticketpolicy.Hold{TenantID: tenantID, IntegrationID: integrationID, FindingID: f.ID()}
	if v := p.Evaluate(ticketpolicy.SignalsOf(f)); !v.Pass {
		hold.Reason, hold.Detail = ticketpolicy.ReasonBelowThreshold, v.Reason
		if v.Reason == "not_open" {
			// A closed finding is not ticketed and not worth a hold.
			return nil, &hold, nil
		}
		return nil, &hold, g.repo.PutHold(ctx, hold)
	}
	reserved, err := g.repo.Reserve(ctx, tenantID, integrationID, p.DailyCap)
	if err != nil {
		return nil, nil, err
	}
	if !reserved {
		hold.Reason = ticketpolicy.ReasonDailyCap
		return nil, &hold, g.repo.PutHold(ctx, hold)
	}
	in.IntegrationID = integrationID.String()
	info, err := g.sync.CreateTicketFromFinding(ctx, in)
	if err != nil {
		g.release(ctx, tenantID, integrationID)
		return nil, nil, err
	}
	g.clear(ctx, tenantID, integrationID, f.ID())
	return info, nil, nil
}

// ManualCreate is a person's "Create ticket". Below the threshold it creates
// only with confirm; without it, it returns the BelowThreshold and creates
// nothing. On a confirmed create below the threshold, below is non-nil so
// the caller can audit it. The daily cap never applies to people.
func (g *PolicyGate) ManualCreate(ctx context.Context, in CreateTicketInput, confirm bool) (info *TicketInfo, below *BelowThreshold, err error) {
	tenantID, integrationID, f, ok, err := g.target(ctx, in)
	if err != nil {
		return nil, nil, err
	}
	if ok {
		p, err := g.repo.Get(ctx, tenantID, integrationID)
		if err != nil {
			return nil, nil, err
		}
		if v := p.Evaluate(ticketpolicy.SignalsOf(f)); v.Reason == ticketpolicy.ReasonBelowThreshold {
			below = &BelowThreshold{IntegrationID: integrationID, Policy: p}
			if !confirm {
				return nil, below, nil
			}
		}
		in.IntegrationID = integrationID.String()
	}
	info, err = g.sync.CreateTicketFromFinding(ctx, in)
	if err != nil {
		return nil, nil, err
	}
	if ok {
		g.clear(ctx, tenantID, integrationID, f.ID())
	}
	return info, below, nil
}

// FindingHolds lists a finding's holds. The caller has checked the person
// may see the finding.
func (g *PolicyGate) FindingHolds(ctx context.Context, tenantID, findingID shared.ID) ([]ticketpolicy.Hold, error) {
	return g.repo.ListFindingHolds(ctx, tenantID, findingID)
}

// ReleaseDue re-checks up to limit due holds and creates the issues that now
// pass, within each integration's cap. It returns how many it created.
func (g *PolicyGate) ReleaseDue(ctx context.Context, limit int) (int, error) {
	due, err := g.repo.DueHolds(ctx, limit, holdRetryAfter)
	if err != nil {
		return 0, err
	}
	created := 0
	disabled := map[shared.ID]bool{}
	for _, c := range due {
		if ctx.Err() != nil {
			return created, ctx.Err()
		}
		if g.modules != nil {
			off, seen := disabled[c.TenantID]
			if !seen {
				off = g.modules.TenantDisabledModules(ctx, c.TenantID.String())[moduledom.ModuleIntegrations]
				disabled[c.TenantID] = off
			}
			if off {
				// Refresh checked_at so a tenant that turned the module
				// off does not keep its holds at the head of every run
				// and starve other tenants' holds.
				if err := g.repo.PutHold(ctx, c.Hold); err != nil {
					g.logger.Warn("refresh ticket hold", "tenant_id", c.TenantID.String(), "error", err)
				}
				continue
			}
		}
		ok, err := g.releaseOne(ctx, c)
		if err != nil {
			g.logger.Warn("ticket hold re-check failed", "tenant_id", c.TenantID.String(),
				"finding_id", c.FindingID.String(), "error", err)
			continue
		}
		if ok {
			created++
		}
	}
	return created, nil
}

func (g *PolicyGate) releaseOne(ctx context.Context, c ticketpolicy.Candidate) (bool, error) {
	if !c.Signals.Open || c.Linked {
		return false, g.repo.DeleteHold(ctx, c.TenantID, c.IntegrationID, c.FindingID)
	}
	hold := c.Hold
	if v := c.Policy.Evaluate(c.Signals); !v.Pass {
		hold.Reason, hold.Detail = ticketpolicy.ReasonBelowThreshold, v.Reason
		return false, g.repo.PutHold(ctx, hold)
	}
	reserved, err := g.repo.Reserve(ctx, c.TenantID, c.IntegrationID, c.Policy.DailyCap)
	if err != nil {
		return false, err
	}
	if !reserved {
		hold.Reason, hold.Detail = ticketpolicy.ReasonDailyCap, ""
		return false, g.repo.PutHold(ctx, hold)
	}
	_, err = g.sync.CreateTicketFromFinding(ctx, CreateTicketInput{
		TenantID: c.TenantID.String(), FindingID: c.FindingID.String(),
		IntegrationID: c.IntegrationID.String(), Route: ticketing.RouteAutomation,
	})
	if err != nil {
		g.release(ctx, c.TenantID, c.IntegrationID)
		hold.Reason, hold.Detail = ticketpolicy.ReasonCreateFailed, failureCode(err)
		if perr := g.repo.PutHold(ctx, hold); perr != nil {
			return false, perr
		}
		return false, err
	}
	return true, g.repo.DeleteHold(ctx, c.TenantID, c.IntegrationID, c.FindingID)
}

// failureCode is the stored, platform-worded cause of a failed create (never
// the upstream text).
func failureCode(err error) string {
	var refused *ticketing.EgressRefusedError
	switch {
	case errors.As(err, &refused):
		return "egress:" + string(refused.Reason)
	case errors.Is(err, shared.ErrValidation):
		return "invalid_destination"
	case errors.Is(err, ErrNoTicketingIntegration):
		return "integration_unavailable"
	default:
		return "tracker_error"
	}
}

func (g *PolicyGate) release(ctx context.Context, tenantID, integrationID shared.ID) {
	if err := g.repo.Release(ctx, tenantID, integrationID); err != nil {
		g.logger.Warn("release ticket slot", "tenant_id", tenantID.String(), "error", err)
	}
}

func (g *PolicyGate) clear(ctx context.Context, tenantID, integrationID, findingID shared.ID) {
	if err := g.repo.DeleteHold(ctx, tenantID, integrationID, findingID); err != nil {
		g.logger.Warn("clear ticket hold", "tenant_id", tenantID.String(), "error", err)
	}
}
