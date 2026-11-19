package cirun

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// What a refused token's value is added to (AllowInTrustConfig).
const (
	// AllowWorkflowRef adds a pipeline definition to the configuration's
	// Pipeline definitions (rules.workflow_refs).
	AllowWorkflowRef = "workflow_ref"
	// AllowRef adds a branch or tag to the configuration's Branches and tags
	// (rules.refs).
	AllowRef = "ref"
)

// ErrAllowNotApplicable refuses a one-click fix the refusal does not support:
// only a refusal by that configuration's pipeline definitions rule
// (workflow_not_allowed) or branches and tags rule (ref_not_allowed) can add
// the refused token's value. Those rules are checked after the organization,
// owner and repository rules, so the token passed them.
var ErrAllowNotApplicable = fmt.Errorf("%w: only a pipeline definition or a branch or tag this configuration refused can be added", shared.ErrValidation)

// ErrAllowRepositoryNotApproved refuses a one-click fix for a project an
// all-projects configuration has not approved: such a configuration skips the
// owner and repository rules, so any project of the instance can produce a
// ref or pipeline-file refusal, and adding its value would widen the rules of
// every approved project.
var ErrAllowRepositoryNotApproved = fmt.Errorf("%w: approve the project first, then add its branch or pipeline file", shared.ErrValidation)

// AllowRepositoryGate says whether a refusal's repository may have its value
// added to cur: false when cur admits every project and the repository is
// not approved on it. The all-projects approval state lives with that
// feature, which sets the gate (SetAllowRepositoryGate); without one every
// refusal's repository is accepted (a configuration naming its owners and
// repositories already admitted this one).
type AllowRepositoryGate func(ctx context.Context, tenantID shared.ID, cur *cirun.TrustConfig, repository string) (bool, error)

// SetAllowRepositoryGate wires the AllowRepositoryGate.
func (s *Service) SetAllowRepositoryGate(g AllowRepositoryGate) { s.allowGate = g }

// ApprovedRepositoryGate is the AllowRepositoryGate of the server: a
// configuration that names its owners and repositories already admitted the
// refused token's project, so it passes; a configuration that admits every
// project (rules.all_repositories) passes only a project it has approved
// (its owner or repository lists name it, as an approval records it).
// Pending, new and blocked projects are not approved, so one click never
// adds a stranger's branch or pipeline file to the rules of every approved
// project.
func ApprovedRepositoryGate(_ context.Context, _ shared.ID, cur *cirun.TrustConfig, repository string) (bool, error) {
	if !cur.Rules.AllRepositories {
		return true, nil
	}
	repository = strings.ToLower(strings.TrimSpace(repository))
	if repository == "" {
		return false, nil
	}
	return cur.Rules.ApprovedRepository(cirun.Claims{Repository: repository}), nil
}

// Allowed is what a one-click fix added.
type Allowed struct {
	Kind  string
	Value string
}

// AllowInTrustConfig adds the value a refused token carried (its pipeline
// definition or ref) to the configuration that refused it. The refusal is
// named by its audit record id and read for the session's tenant (another
// tenant's id is not found); the value is taken from that record, never
// from the caller, and only when that configuration refused it with exactly
// workflow_not_allowed or ref_not_allowed. It is an ordinary change of the
// configuration: the same validation, step-up and audit
// (ci_trust_config.updated with before and after) as UpdateTrustConfig. A
// value already listed changes nothing (changed false).
func (s *Service) AllowInTrustConfig(ctx context.Context, tenantID, id, refusalID shared.ID, a Actor) (*cirun.TrustConfig, Allowed, bool, error) {
	ref, err := s.repo.TokenRefusal(ctx, tenantID, refusalID)
	if err != nil {
		return nil, Allowed{}, false, err
	}
	cur, err := s.repo.GetTrustConfig(ctx, tenantID, id)
	if err != nil {
		return nil, Allowed{}, false, err
	}
	var allowed Allowed
	for _, c := range ref.Configs {
		if c.ID != id.String() {
			continue
		}
		switch c.Code {
		case cirun.RefuseWorkflow:
			allowed = Allowed{Kind: AllowWorkflowRef, Value: strings.TrimSpace(ref.WorkflowDefinition)}
		case cirun.RefuseRef:
			allowed = Allowed{Kind: AllowRef, Value: strings.TrimSpace(ref.Ref)}
		}
	}
	// The record must be this configuration's refusal of a token from its
	// issuer (a configuration re-pointed since does not take the value).
	if allowed.Value == "" || (ref.Issuer != "" && strings.TrimRight(ref.Issuer, "/") != strings.TrimRight(cur.Issuer, "/")) {
		return nil, Allowed{}, false, ErrAllowNotApplicable
	}
	if s.allowGate != nil {
		ok, err := s.allowGate(ctx, tenantID, cur, ref.Repository)
		if err != nil {
			return nil, Allowed{}, false, err
		}
		if !ok {
			return nil, Allowed{}, false, ErrAllowRepositoryNotApproved
		}
	}
	rules := cur.Rules
	switch allowed.Kind {
	case AllowWorkflowRef:
		if slices.Contains(rules.WorkflowRefs, allowed.Value) {
			return cur, allowed, false, nil
		}
		rules.WorkflowRefs = append(slices.Clone(rules.WorkflowRefs), allowed.Value)
	case AllowRef:
		if slices.Contains(rules.Refs, allowed.Value) {
			return cur, allowed, false, nil
		}
		rules.Refs = append(slices.Clone(rules.Refs), allowed.Value)
	}
	enabled, manage := cur.Enabled, cur.ManageScope
	next, err := s.UpdateTrustConfig(ctx, tenantID, id, TrustConfigInput{Name: cur.Name, Provider: string(cur.Provider),
		Issuer: cur.Issuer, Audience: cur.Audience, DefaultBranch: cur.DefaultBranch, Rules: rules,
		Enabled: &enabled, ManageScope: &manage}, a)
	if err != nil {
		return nil, Allowed{}, false, err
	}
	return next, allowed, true, nil
}
