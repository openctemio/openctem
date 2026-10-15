package handler

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/brand"
	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The TLP limit for AI applications (design: docs/rfcs/RFC-016-mcp-server.md,
// organization policy in docs/rfcs/RFC-062-mcp-authorization.md): a pentest
// campaign whose TLP is above the organization's limit (default amber), or
// whose lead turned AI assistants off, is never sent to an AI client. Every
// pentest tool and prompt refuses its content with campaign_restricted
// after the membership check (a non-member still gets not_found), the
// campaign lists leave it out and say how many they left out, and the
// generic finding list leaves out its findings in SQL.

// mcpAIPolicyReader returns an organization's MCP policy.
type mcpAIPolicyReader interface {
	MCPPolicy(ctx context.Context, tenantID shared.ID) (tenantdom.MCPSettings, error)
}

// SetAIPolicy makes the pentest tools follow the organization's TLP limit
// for AI applications. Without it the default limit (amber) applies.
func (h *MCPHandler) SetAIPolicy(r mcpAIPolicyReader) { h.aiPolicy = r }

// mcpErrCampaignRestricted is the code of a refused restricted campaign.
const mcpErrCampaignRestricted = "campaign_restricted"

// mcpRestrictedError is a campaign kept away from AI applications.
type mcpRestrictedError struct{ msg string }

func (e mcpRestrictedError) Error() string { return e.msg }

// aiMaxTLP is the organization's TLP limit for AI applications. A policy
// read error is returned (the caller fails closed).
func (h *MCPHandler) aiMaxTLP(ctx context.Context, tenantID string) (pentestdom.TLP, error) {
	if h.aiPolicy == nil {
		return pentestdom.TLP(tenantdom.DefaultMCPMaxTLP), nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return "", toolInputError{"invalid tenant"}
	}
	p, err := h.aiPolicy.MCPPolicy(ctx, tid)
	if err != nil {
		return "", fmt.Errorf("read the AI policy: %w", err)
	}
	return pentestdom.TLP(p.AIMaxTLP()), nil
}

// aiAllowedTLPs are the TLP levels AI applications may read.
func (h *MCPHandler) aiAllowedTLPs(ctx context.Context, tenantID string) ([]string, error) {
	maxTLP, err := h.aiMaxTLP(ctx, tenantID)
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

// checkCampaignAI refuses a campaign kept away from AI applications.
func (h *MCPHandler) checkCampaignAI(ctx context.Context, tenantID string, c *pentestdom.Campaign) error {
	if c.AIAssistantsDisabled() {
		return mcpRestrictedError{"the campaign lead turned AI assistants off for this campaign, so its content " +
			"is not sent to AI applications. Work on it in " + brand.Name() + "."}
	}
	maxTLP, err := h.aiMaxTLP(ctx, tenantID)
	if err != nil {
		return err
	}
	if c.TLP().Above(maxTLP) {
		return mcpRestrictedError{fmt.Sprintf("this campaign is %s and your organization sends pentest campaigns "+
			"to AI applications up to %s only, so its content is not sent here. Work on it in %s.",
			c.TLP().Label(), maxTLP.Label(), brand.Name())}
	}
	return nil
}

// checkFindingAI refuses a pentest finding of a restricted campaign. Other
// findings pass.
func (h *MCPHandler) checkFindingAI(ctx context.Context, tenantID string, f *vulnerability.Finding) error {
	if f == nil || f.Source() != vulnerability.FindingSourcePentest {
		return nil
	}
	if f.PentestCampaignID() == nil || h.pentest == nil {
		// A pentest finding without a campaign is never sent.
		return errMCPNotFound
	}
	c, err := h.pentest.GetCampaign(ctx, tenantID, f.PentestCampaignID().String())
	if err != nil {
		return err
	}
	return h.checkCampaignAI(ctx, tenantID, c)
}

// mcpRestrictedHiddenNotice explains campaigns a list left out.
func mcpRestrictedHiddenNotice(n int64, maxTLP pentestdom.TLP) string {
	return fmt.Sprintf("%d of your campaigns are not listed: their TLP is above %s, the limit your organization "+
		"set for AI applications, or their lead turned AI assistants off. Open them in %s.", n, maxTLP.Label(), brand.Name())
}
