// Package aipolicy decides whether finding content may leave the platform for
// an AI model: the organization's own AI application over MCP, or the
// platform's AI triage. Both callers use this one policy, so a pentest
// campaign the organization keeps away from AI is kept away from every AI
// path. Design: docs/architecture/ai-triage.md (data egress); the TLP limit
// is the organization's MCP setting (docs/rfcs/RFC-062-mcp-authorization.md).
package aipolicy

import (
	"context"
	"errors"
	"fmt"

	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ErrRestricted matches every refusal of this policy (errors.Is).
var ErrRestricted = errors.New("ai_policy_restricted")

// Reason is the stable code of a refusal.
type Reason string

const (
	// ReasonCampaignAIOff: the campaign lead turned AI assistants off.
	ReasonCampaignAIOff Reason = "campaign_ai_disabled"
	// ReasonCampaignTLP: the campaign's TLP is above the organization's
	// limit for AI.
	ReasonCampaignTLP Reason = "campaign_tlp_above_limit"
	// ReasonNoCampaign: a pentest finding without a campaign (or one whose
	// campaign cannot be read) is never sent.
	ReasonNoCampaign Reason = "pentest_without_campaign"
)

// RestrictedError is a refusal: the content stays on the platform.
type RestrictedError struct {
	Reason      Reason
	CampaignTLP pentestdom.TLP
	MaxTLP      pentestdom.TLP
}

func (e *RestrictedError) Error() string {
	switch e.Reason {
	case ReasonCampaignTLP:
		return fmt.Sprintf("%s: campaign is %s, organization limit for AI is %s", ErrRestricted, e.CampaignTLP.Label(), e.MaxTLP.Label())
	default:
		return fmt.Sprintf("%s: %s", ErrRestricted, e.Reason)
	}
}

// Is makes errors.Is(err, ErrRestricted) true.
func (e *RestrictedError) Is(target error) bool { return target == ErrRestricted }

// PolicyReader returns an organization's MCP policy, which holds its TLP
// limit for AI.
type PolicyReader interface {
	MCPPolicy(ctx context.Context, tenantID shared.ID) (tenantdom.MCPSettings, error)
}

// CampaignReader reads a pentest campaign of the tenant.
type CampaignReader interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*pentestdom.Campaign, error)
}

// Egress is the organization's AI data-egress policy.
type Egress struct {
	policies  PolicyReader
	campaigns CampaignReader
}

// New builds the policy. A nil policy reader applies the default TLP limit
// (amber); a nil campaign reader refuses every pentest finding passed to
// CheckFinding (callers that load campaigns themselves use CheckCampaign).
func New(policies PolicyReader, campaigns CampaignReader) *Egress {
	return &Egress{policies: policies, campaigns: campaigns}
}

// MaxTLP is the organization's TLP limit for AI. A read error is returned
// so the caller fails closed.
func (e *Egress) MaxTLP(ctx context.Context, tenantID shared.ID) (pentestdom.TLP, error) {
	if e == nil || e.policies == nil {
		return pentestdom.TLP(tenantdom.DefaultMCPMaxTLP), nil
	}
	p, err := e.policies.MCPPolicy(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("read the AI policy: %w", err)
	}
	return pentestdom.TLP(p.AIMaxTLP()), nil
}

// AllowedTLPs are the TLP levels whose campaigns may be sent to AI.
func (e *Egress) AllowedTLPs(ctx context.Context, tenantID shared.ID) ([]string, error) {
	maxTLP, err := e.MaxTLP(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	levels := pentestdom.TLPsUpTo(maxTLP)
	out := make([]string, len(levels))
	for i, l := range levels {
		out[i] = string(l)
	}
	return out, nil
}

// CampaignAllowed is the decision for one campaign under a limit: nil, or a
// *RestrictedError. The lead's switch wins over the TLP.
func CampaignAllowed(c *pentestdom.Campaign, maxTLP pentestdom.TLP) error {
	if c == nil {
		return &RestrictedError{Reason: ReasonNoCampaign, MaxTLP: maxTLP}
	}
	if c.AIAssistantsDisabled() {
		return &RestrictedError{Reason: ReasonCampaignAIOff, CampaignTLP: c.TLP(), MaxTLP: maxTLP}
	}
	if c.TLP().Above(maxTLP) {
		return &RestrictedError{Reason: ReasonCampaignTLP, CampaignTLP: c.TLP(), MaxTLP: maxTLP}
	}
	return nil
}

// CheckCampaign refuses a campaign kept away from AI.
func (e *Egress) CheckCampaign(ctx context.Context, tenantID shared.ID, c *pentestdom.Campaign) error {
	maxTLP, err := e.MaxTLP(ctx, tenantID)
	if err != nil {
		return err
	}
	return CampaignAllowed(c, maxTLP)
}

// CheckFinding refuses a pentest finding of a campaign kept away from AI.
// Other findings pass. The campaign is read as the system (the caller has
// already applied the person's access); a campaign that cannot be found is
// refused, any other read error is returned (fail closed).
func (e *Egress) CheckFinding(ctx context.Context, tenantID shared.ID, f *vulnerability.Finding) error {
	if f == nil || f.Source() != vulnerability.FindingSourcePentest {
		return nil
	}
	if e == nil || e.campaigns == nil || f.PentestCampaignID() == nil {
		return &RestrictedError{Reason: ReasonNoCampaign}
	}
	c, err := e.campaigns.GetByID(ctx, tenantID, *f.PentestCampaignID())
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return &RestrictedError{Reason: ReasonNoCampaign}
		}
		return fmt.Errorf("read the pentest campaign: %w", err)
	}
	return e.CheckCampaign(ctx, tenantID, c)
}
