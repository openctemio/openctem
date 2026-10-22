package aitriage

// Bug-bounty reports and AI triage (RFC-121 D13): the text of a report is
// written by an outside person, so it goes to the model only when a person
// asks, and the verdict never starts anything on its own.
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-121-bug-bounty-reports.md

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ErrPersonRequestOnly: a bug-bounty report is AI-triaged only at a
// person's request; auto-triage, workflow actions and requests without a
// user are refused. It is an AI data policy refusal (403).
var ErrPersonRequestOnly = fmt.Errorf("%w: a bug-bounty report goes to AI triage only when a person asks for it", ErrPolicyRestricted)

// personRequestOnly reports whether f may reach the model only at a
// person's request, with no automatic follow-up on the verdict.
func personRequestOnly(f *vulnerability.Finding) bool {
	return f != nil && f.Source() == vulnerability.FindingSourceBugBounty
}

// refuseUnrequested is the gate of every entry path: f without a requesting
// person (requestedBy nil) is refused when it is a bug-bounty report.
func refuseUnrequested(f *vulnerability.Finding, requestedBy *shared.ID) error {
	if personRequestOnly(f) && requestedBy == nil {
		return ErrPersonRequestOnly
	}
	return nil
}

// bulkPolicy is the per-finding policy of a bulk request: the organization's
// AI data policy, then the person-request rule.
func (s *AITriageService) bulkPolicy(ctx context.Context, tenantID shared.ID, f *vulnerability.Finding, requestedBy *shared.ID) error {
	if err := s.checkEgress(ctx, tenantID, f); err != nil {
		return err
	}
	return refuseUnrequested(f, requestedBy)
}
