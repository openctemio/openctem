package handler

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/aipolicy"
	"github.com/openctemio/openctem/api/pkg/brand"
	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
type mcpAIPolicyReader = aipolicy.PolicyReader

// SetAIPolicy makes the pentest tools follow the organization's TLP limit
// for AI applications. Without it the default limit (amber) applies. The
// decision is the shared AI egress policy (internal/app/aipolicy), the same
// one AI triage applies.
func (h *MCPHandler) SetAIPolicy(r mcpAIPolicyReader) { h.aiPolicy = aipolicy.New(r, nil) }

// mcpErrCampaignRestricted is the code of a refused restricted campaign.
const mcpErrCampaignRestricted = "campaign_restricted"

// mcpRestrictedError is a campaign kept away from AI applications.
type mcpRestrictedError struct{ msg string }

func (e mcpRestrictedError) Error() string { return e.msg }

// aiMaxTLP is the organization's TLP limit for AI applications. A policy
// read error is returned (the caller fails closed).
func (h *MCPHandler) aiMaxTLP(ctx context.Context, tenantID string) (pentestdom.TLP, error) {
	if h.aiPolicy == nil {
		return h.aiPolicy.MaxTLP(ctx, shared.ID{}) // the default limit
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return "", toolInputError{"invalid tenant"}
	}
	return h.aiPolicy.MaxTLP(ctx, tid)
}

// aiAllowedTLPs are the TLP levels AI applications may read.
func (h *MCPHandler) aiAllowedTLPs(ctx context.Context, tenantID string) ([]string, error) {
	if h.aiPolicy == nil {
		return h.aiPolicy.AllowedTLPs(ctx, shared.ID{}) // the default limit
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, toolInputError{"invalid tenant"}
	}
	return h.aiPolicy.AllowedTLPs(ctx, tid)
}

// checkCampaignAI refuses a campaign kept away from AI applications.
func (h *MCPHandler) checkCampaignAI(ctx context.Context, tenantID string, c *pentestdom.Campaign) error {
	maxTLP, err := h.aiMaxTLP(ctx, tenantID)
	if err != nil {
		return err
	}
	var re *aipolicy.RestrictedError
	if err := aipolicy.CampaignAllowed(c, maxTLP); errors.As(err, &re) {
		if re.Reason == aipolicy.ReasonCampaignAIOff {
			return mcpRestrictedError{"the campaign lead turned AI assistants off for this campaign, so its content " +
				"is not sent to AI applications. Work on it in " + brand.Name() + "."}
		}
		return mcpRestrictedError{fmt.Sprintf("this campaign is %s and your organization sends pentest campaigns "+
			"to AI applications up to %s only, so its content is not sent here. Work on it in %s.",
			re.CampaignTLP.Label(), maxTLP.Label(), brand.Name())}
	}
	return nil
}

// checkFindingAI refuses a pentest finding of a restricted campaign. Other
// findings pass. The campaign is read through the pentest reader, which
// applies the person's campaign membership first.
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
