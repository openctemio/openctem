package cirun

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// What a refused token's value can be added to (AllowInTrustConfig).
const (
	// AllowWorkflowRef adds a pipeline definition to the configuration's
	// Pipeline definitions (rules.workflow_refs).
	AllowWorkflowRef = "workflow_ref"
	// AllowRef adds a branch or tag to the configuration's Branches and tags
	// (rules.refs).
	AllowRef = "ref"
)

// ErrAllowKind refuses an unknown kind of AllowInTrustConfig.
var ErrAllowKind = fmt.Errorf("%w: kind must be workflow_ref or ref", shared.ErrValidation)

// AllowInTrustConfig adds one value a refused token carried (a pipeline
// definition or a ref) to a trust configuration's list. It is an ordinary
// change of the configuration: the same validation, step-up and audit
// (ci_trust_config.updated with before and after) as UpdateTrustConfig. A
// value already listed changes nothing (changed false).
func (s *Service) AllowInTrustConfig(ctx context.Context, tenantID, id shared.ID, kind, value string, a Actor) (*cirun.TrustConfig, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, false, fmt.Errorf("%w: value is required", shared.ErrValidation)
	}
	cur, err := s.repo.GetTrustConfig(ctx, tenantID, id)
	if err != nil {
		return nil, false, err
	}
	rules := cur.Rules
	switch kind {
	case AllowWorkflowRef:
		if slices.Contains(rules.WorkflowRefs, value) {
			return cur, false, nil
		}
		rules.WorkflowRefs = append(slices.Clone(rules.WorkflowRefs), value)
	case AllowRef:
		if slices.Contains(rules.Refs, value) {
			return cur, false, nil
		}
		rules.Refs = append(slices.Clone(rules.Refs), value)
	default:
		return nil, false, ErrAllowKind
	}
	enabled, manage := cur.Enabled, cur.ManageScope
	next, err := s.UpdateTrustConfig(ctx, tenantID, id, TrustConfigInput{Name: cur.Name, Provider: string(cur.Provider),
		Issuer: cur.Issuer, Audience: cur.Audience, DefaultBranch: cur.DefaultBranch, Rules: rules,
		Enabled: &enabled, ManageScope: &manage}, a)
	if err != nil {
		return nil, false, err
	}
	return next, true, nil
}
