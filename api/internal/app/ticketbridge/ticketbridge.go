// Package ticketbridge adapts the finding service's inbound ticket path
// (status moves and disposition requests driven by a tracker) to the ticket
// services' own narrow interfaces. The ticket services cannot import the
// finding package without an import cycle, so the composition root and the
// service-path tests share these adapters instead of each carrying a copy.
package ticketbridge

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Jira adapts the finding service to the Jira sync service.
type Jira struct{ Vuln *finding.VulnerabilityService }

func (a Jira) ApplyTicketStatus(ctx context.Context, tenantID shared.ID, ids []shared.ID,
	target vulnerability.FindingStatus, integration, ref, externalActor string,
) ([]shared.ID, []jira.InboundRefusal, error) {
	out, err := a.Vuln.ApplyTicketStatus(ctx, tenantID, ids, target, integration, ref, externalActor)
	if err != nil {
		return nil, nil, err
	}
	refused := make([]jira.InboundRefusal, 0, len(out.Refused))
	for _, r := range out.Refused {
		refused = append(refused, jira.InboundRefusal{FindingID: r.FindingID, Reason: r.Reason})
	}
	return out.Applied, refused, nil
}

func (a Jira) RequestTicketDisposition(ctx context.Context, tenantID shared.ID, ids []shared.ID,
	target vulnerability.FindingStatus, integration, ref, externalActor string,
) ([]shared.ID, []shared.ID, []jira.InboundRefusal, error) {
	out, err := a.Vuln.RequestTicketDisposition(ctx, tenantID, ids, target, integration, ref, externalActor)
	if err != nil {
		return nil, nil, nil, err
	}
	refused := make([]jira.InboundRefusal, 0, len(out.Refused))
	for _, r := range out.Refused {
		refused = append(refused, jira.InboundRefusal{FindingID: r.FindingID, Reason: r.Reason})
	}
	return out.Requested, out.Pending, refused, nil
}

// GitHub adapts the finding service to the GitHub ticket service.
type GitHub struct{ Vuln *finding.VulnerabilityService }

func (a GitHub) ApplyTicketStatus(ctx context.Context, tenantID shared.ID, ids []shared.ID,
	target vulnerability.FindingStatus, integration, ref, externalActor string,
) (*ticketing.InboundStatusOutcome, error) {
	out, err := a.Vuln.ApplyTicketStatus(ctx, tenantID, ids, target, integration, ref, externalActor)
	if err != nil {
		return nil, err
	}
	refused := make([]ticketing.InboundRefusal, 0, len(out.Refused))
	for _, r := range out.Refused {
		refused = append(refused, ticketing.InboundRefusal{FindingID: r.FindingID, Reason: r.Reason})
	}
	return &ticketing.InboundStatusOutcome{Applied: out.Applied, Refused: refused}, nil
}

func (a GitHub) RequestTicketDisposition(ctx context.Context, tenantID shared.ID, ids []shared.ID,
	target vulnerability.FindingStatus, integration, ref, externalActor string,
) (*ticketing.InboundRequestOutcome, error) {
	out, err := a.Vuln.RequestTicketDisposition(ctx, tenantID, ids, target, integration, ref, externalActor)
	if err != nil {
		return nil, err
	}
	refused := make([]ticketing.InboundRefusal, 0, len(out.Refused))
	for _, r := range out.Refused {
		refused = append(refused, ticketing.InboundRefusal{FindingID: r.FindingID, Reason: r.Reason})
	}
	return &ticketing.InboundRequestOutcome{Requested: out.Requested, Pending: out.Pending, Refused: refused}, nil
}
