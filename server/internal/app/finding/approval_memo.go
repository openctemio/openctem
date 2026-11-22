package finding

// A per-call memo of the organization-wide lookups the approval policy makes
// for every finding of one request (bulk dismiss: up to 500 findings). The
// evaluation stays evaluateFindingRequest; the helpers it calls consult the
// memo when the context carries one for the same tenant:
//
//   - the organization's policy and levels (one settings read per call);
//   - whether a requester is an AI agent;
//   - the security pool and the approver directory (once per call);
//   - each approver's data scope, resolved once over every finding of the call
//     (one query per approver, not one per approver and finding);
//   - the policy facts of every finding of the call (one query);
//   - the findings themselves (loaded once by the caller).
//
// Threat model: a memo must never let a stale or foreign answer decide. It
// lives only for one service call, is keyed by tenant (a lookup for another
// tenant ignores it), answers only for the finding ids the call registered,
// fails closed like the uncached path (an approver whose scope cannot be read
// is not a candidate), and is never used by the in-transaction re-check that
// guards a decision made alone (recheckSinglePerson reads the database). A
// raced decision drops the cached policy (forgetOrg) before it re-evaluates.

import (
	"context"
	"errors"
	"sync"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type approvalMemoKey struct{}

// approvalMemo is the cache of one call. Safe for concurrent use.
type approvalMemo struct {
	tenant shared.ID
	ids    []shared.ID
	idSet  map[shared.ID]bool

	mu            sync.Mutex
	org           *orgPolicy
	aiAgent       map[shared.ID]bool
	pool          map[shared.ID]bool
	approvers     []FindingApprover
	approversRead bool
	approverScope map[shared.ID]func(shared.ID) bool
	facts         map[shared.ID]PolicyFacts
	factsRead     bool
	findings      map[shared.ID]*vulnerability.Finding
}

// withApprovalMemo returns ctx carrying a memo for tenantID over findingIDs.
func withApprovalMemo(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (context.Context, *approvalMemo) {
	m := &approvalMemo{
		tenant: tenantID, ids: findingIDs, idSet: make(map[shared.ID]bool, len(findingIDs)),
		aiAgent: map[shared.ID]bool{}, approverScope: map[shared.ID]func(shared.ID) bool{},
		findings: map[shared.ID]*vulnerability.Finding{},
	}
	for _, id := range findingIDs {
		m.idSet[id] = true
	}
	return context.WithValue(ctx, approvalMemoKey{}, m), m
}

// approvalMemoFor is the memo of ctx for tenantID (nil when none, or when it
// is another tenant's).
func approvalMemoFor(ctx context.Context, tenantID shared.ID) *approvalMemo {
	m, _ := ctx.Value(approvalMemoKey{}).(*approvalMemo)
	if m == nil || m.tenant != tenantID {
		return nil
	}
	return m
}

// covers reports whether the memo answers for finding id.
func (m *approvalMemo) covers(id shared.ID) bool { return m != nil && m.idSet[id] }

// putFindings registers the findings the caller loaded.
func (m *approvalMemo) putFindings(fs []*vulnerability.Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range fs {
		if f != nil && f.TenantID() == m.tenant && m.idSet[f.ID()] {
			m.findings[f.ID()] = f
		}
	}
}

// forgetOrg drops the cached policy: the next evaluation reads it again
// (after a decision raced with a raised level).
func (m *approvalMemo) forgetOrg() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.org = nil
	m.mu.Unlock()
}

func (m *approvalMemo) cachedOrgPolicy() (orgPolicy, bool) {
	if m == nil {
		return orgPolicy{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.org == nil {
		return orgPolicy{}, false
	}
	return *m.org, true
}

func (m *approvalMemo) setOrg(op orgPolicy) {
	m.mu.Lock()
	m.org = &op
	m.mu.Unlock()
}

func (m *approvalMemo) cachedAIAgent(id shared.ID) (isAI, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	isAI, ok = m.aiAgent[id]
	return isAI, ok
}

func (m *approvalMemo) setAIAgent(id shared.ID, isAI bool) {
	m.mu.Lock()
	m.aiAgent[id] = isAI
	m.mu.Unlock()
}

func (m *approvalMemo) cachedPoolMembers() (map[shared.ID]bool, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pool, m.pool != nil
}

func (m *approvalMemo) setPool(p map[shared.ID]bool) {
	m.mu.Lock()
	m.pool = p
	m.mu.Unlock()
}

// policyFactsManyReader reads the policy facts of many findings of one tenant
// in one query (*postgres.FindingApprovalRepository). A finding of another
// tenant, or one that no longer exists, has no entry.
type policyFactsManyReader interface {
	PolicyFactsMany(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (map[shared.ID]PolicyFacts, error)
}

// policyFacts answers the facts of a covered finding, reading every covered
// finding's facts on the first call. ok is false when the memo cannot answer
// (the caller reads the one finding itself).
func (m *approvalMemo) policyFacts(ctx context.Context, r policyFactsManyReader, id shared.ID) (PolicyFacts, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.factsRead {
		facts, err := r.PolicyFactsMany(ctx, m.tenant, m.ids)
		if err != nil {
			return PolicyFacts{}, false, err
		}
		m.facts, m.factsRead = facts, true
	}
	pf, ok := m.facts[id]
	return pf, ok, nil
}

// findingApprovers answers the approver directory, read once.
func (m *approvalMemo) findingApprovers(ctx context.Context, dir FindingApproverDirectory) ([]FindingApprover, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.approversRead {
		all, err := dir.FindingApprovers(ctx, m.tenant)
		if err != nil {
			return nil, err
		}
		m.approvers, m.approversRead = all, true
	}
	return m.approvers, nil
}

// approverSees reports whether approver uid has finding id in their data
// scope. The scope is resolved once per approver over every covered finding
// (FilterFindings, the batch form of AssertFindingForUser); a failure
// answers false (fail closed) and is not cached.
func (s *VulnerabilityService) approverSees(ctx context.Context, m *approvalMemo, uid, findingID shared.ID) bool {
	m.mu.Lock()
	in, ok := m.approverScope[uid]
	m.mu.Unlock()
	if !ok {
		scope, err := s.dataScope.ForUser(ctx, m.tenant, uid)
		if err == nil {
			in, err = s.dataScope.FilterFindings(ctx, scope, m.ids)
		}
		if err != nil {
			if !errors.Is(err, shared.ErrNotFound) {
				s.logger.Warn("approval policy: data scope", "error", logger.SanitizeError(err))
			}
			return false
		}
		m.mu.Lock()
		m.approverScope[uid] = in
		m.mu.Unlock()
	}
	return in(findingID)
}

// memoFinding reads a finding of the tenant: from the call's memo when it
// holds it, from the repository otherwise.
func (s *VulnerabilityService) memoFinding(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, error) {
	if m := approvalMemoFor(ctx, tenantID); m != nil {
		m.mu.Lock()
		f, ok := m.findings[findingID]
		m.mu.Unlock()
		if ok {
			return f, nil
		}
	}
	return s.findingRepo.GetByID(ctx, tenantID, findingID)
}
