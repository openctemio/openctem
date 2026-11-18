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
