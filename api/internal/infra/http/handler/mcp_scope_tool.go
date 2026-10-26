package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/brand"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// check_scope answers one question for an outside AI client: may I test this
// target at this intensity? It asks the same authority a scan does
// (scopeauth), so the answer matches the one a scan would get. It only reads:
// no tool of this server widens a scope, the human path (approvals, step-up,
// audit) stays the only way. Design: docs/architecture/mcp-authorization.md.

// Decisions check_scope returns.
const (
	scopeAllowed     = "allowed"
	scopeRefused     = "refused"
	scopePassiveOnly = "passive_only"
)

// Reason codes. They never carry scope entries, patterns or deny-list data.
const (
	scopeReasonNoEntry        = "no_scope_entry"
	scopeReasonTier           = "intensity_above_entry"
	scopeReasonDenied         = "platform_deny_list"
	scopeReasonProgramOnly    = "program_only"
	scopeReasonLookupFailed   = "scope_lookup_failed"
	scopeReasonProgramUnknown = "program_not_covering"
	scopeReasonRateLimited    = "rate_limited"
)

// mcpScopeLimitPerMinute and the burst cap how fast one connection can ask,
// so the tool cannot be used to map the organization's scope by brute force.
const (
	mcpScopeLimitPerMinute = 30
	mcpScopeLimitBurst     = 10
)

// mcpProgramMembers lists the programs a person belongs to
// (*postgres.BountyProgramRepository).
type mcpProgramMembers interface {
	MemberProgramIDs(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error)
}

// SetScopeCheck enables check_scope. Without both sources it is not listed.
// programs is optional: without it a program-only target is always refused.
func (h *MCPHandler) SetScopeCheck(targets scopeauth.Targets, roots scopeauth.Roots, programs mcpProgramMembers) {
	if targets == nil || roots == nil {
		return
	}
	h.scopeTargets, h.scopeRoots, h.scopePrograms = targets, roots, programs
	h.scopeLimiter = newTenantRateLimiter(mcpScopeLimitPerMinute, mcpScopeLimitBurst)
	h.tools = append(h.tools, h.buildScopeTool())
}

func (h *MCPHandler) buildScopeTool() mcpTool {
	return mcpTool{
		Name: "check_scope",
		Description: "Ask whether a target (domain, IP, CIDR or URL) may be tested at an intensity " +
			"(passive, active or intrusive) under this organization's authorized scope. The answer is the " +
			"platform's decision, the same one a scan gets: allowed, passive_only or refused, with reason codes " +
			"and a hint for the person. Read only: no tool widens a scope, and a refusal is not a target " +
			"defense, so do not retry variations of it. Calls are rate limited per connection.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"target":{"type":"string","maxLength":512,"description":"domain, IP, CIDR or URL"},` +
			`"intensity":{"type":"string","enum":["passive","active","intrusive"],"description":"default active"},` +
			`"program_id":{"type":"string","format":"uuid","description":"bug-bounty program the work is for, when the target is covered by a program rule"}` +
			`},"required":["target"]}`),
		RequiredPerm: string(permission.ScopeRead),
		call:         h.toolCheckScope,
	}
}

type scopeDecision struct {
	Decision string    `json:"decision"`
	Via      *scopeVia `json:"via,omitempty"`
	Reasons  []string  `json:"reasons"`
	FixHint  string    `json:"fix_hint,omitempty"`
	Notice   string    `json:"notice"`
	// RetryAfterSeconds is set for a rate-limited call only.
	RetryAfterSeconds int `json:"retry_after_seconds,omitempty"`
}

type scopeVia struct {
	Kind  string `json:"kind"`
	ID    string `json:"id,omitempty"`
	Proof string `json:"proof,omitempty"`
}

const scopeNotice = "This is the platform's scope decision, not a defense of the target: do not retry variations of a refusal."

func refusedScope(hint string, reasons ...string) scopeDecision {
	return scopeDecision{Decision: scopeRefused, Reasons: reasons, FixHint: hint, Notice: scopeNotice}
}

// scopeLimitKey is the connection the rate limit counts: the OAuth grant, or
// the API key, inside the tenant.
func scopeLimitKey(ctx context.Context, tenantID string) string {
	if p := middleware.GetMCPPrincipal(ctx); p != nil && p.GrantID != "" {
		return tenantID + "/grant/" + p.GrantID
	}
	return tenantID + "/key/" + middleware.GetAPIKeyID(ctx)
}

func (h *MCPHandler) toolCheckScope(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var args struct {
		Target    string `json:"target"`
		Intensity string `json:"intensity"`
		ProgramID string `json:"program_id"`
	}
	if err := parseToolArgs(raw, &args); err != nil {
		return nil, err
	}
	target := strings.TrimSpace(args.Target)
	if target == "" || len(target) > 512 {
		return nil, toolInputError{"target is required (domain, IP, CIDR or URL, at most 512 characters)"}
	}
	tier := scopedom.TierActive
	switch args.Intensity {
	case "", "active":
	case "passive":
		tier = scopedom.TierPassive
	case "intrusive":
		tier = scopedom.TierIntrusive
	default:
		return nil, toolInputError{"intensity must be passive, active or intrusive"}
	}
	var program shared.ID
	if args.ProgramID != "" {
		id, err := shared.IDFromString(args.ProgramID)
		if err != nil {
			return nil, toolInputError{"program_id must be a UUID"}
		}
		program = id
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, toolInputError{"invalid tenant"}
	}
	if h.scopeLimiter == nil {
		return nil, shared.ErrNotFound
	}
	if ok, retry := h.scopeLimiter.allow(scopeLimitKey(ctx, tenantID), time.Now()); !ok {
		d := refusedScope("Too many scope checks from this connection. Repeated asks do not change the answer.", scopeReasonRateLimited)
		d.RetryAfterSeconds = retry
		return d, nil
	}

	return h.decideScope(ctx, tid, target, tier, program), nil
}

// decideScope never returns an error: any lookup failure is a refusal.
func (h *MCPHandler) decideScope(ctx context.Context, tenantID shared.ID, target string, tier scopedom.Tier, program shared.ID) scopeDecision {
	hint := "Ask someone who manages Scoping in " + brand.Name() + " to review the scope entries."
	if scopedom.DefaultGuardrails().Denies(target) {
		return refusedScope("The platform never allows this target to be tested.", scopeReasonDenied)
	}
	auth, err := scopeauth.Load(ctx, tenantID, h.scopeTargets, h.scopeRoots)
	if err != nil {
		h.logger.Warn("mcp check_scope: authority lookup failed", "error", err.Error())
		return refusedScope("The scope could not be read; nothing is allowed until it can. Try again later.", scopeReasonLookupFailed)
	}

	via, covered := auth.CoversAt(target, tier)
	if !covered {
		// Covered at a lower intensity? Then say so, never more than that.
		if tier > scopedom.TierPassive {
			if _, ok := auth.CoversAt(target, scopedom.TierPassive); ok && !auth.ProgramOnly(target) {
				d := refusedScope(hint, scopeReasonTier)
				d.Decision = scopePassiveOnly
				return d
			}
		}
		return refusedScope(hint, scopeReasonNoEntry)
	}
	if auth.ProgramOnly(target) {
		// Program rules apply to the people of that program only.
		if program.IsZero() || h.scopePrograms == nil {
			return refusedScope("This target is covered by a bug-bounty program rule only: pass the program_id of a program you belong to.", scopeReasonProgramOnly)
		}
		member, err := h.callerInProgram(ctx, tenantID, program)
		if err != nil {
			h.logger.Warn("mcp check_scope: program lookup failed", "error", err.Error())
			return refusedScope("The scope could not be read; nothing is allowed until it can. Try again later.", scopeReasonLookupFailed)
		}
		if !member || !auth.CoveredByPrograms(target, map[shared.ID]bool{program: true}) {
			return refusedScope("No rule of that program covers this target for you.", scopeReasonProgramUnknown)
		}
		return scopeDecision{Decision: scopeAllowed, Via: &scopeVia{Kind: "program", ID: program.String()}, Reasons: []string{}, Notice: scopeNotice}
	}
	return scopeDecision{
		Decision: scopeAllowed,
		Via:      &scopeVia{Kind: via.Kind, ID: via.ID, Proof: via.Proof},
		Reasons:  []string{},
		Notice:   scopeNotice,
	}
}

func (h *MCPHandler) callerInProgram(ctx context.Context, tenantID, program shared.ID) (bool, error) {
	user, err := shared.IDFromString(middleware.GetUserID(ctx))
	if err != nil {
		return false, err // no person behind the call: refused as a failed lookup
	}
	ids, err := h.scopePrograms.MemberProgramIDs(ctx, tenantID, user)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if id == program {
			return true, nil
		}
	}
	return false, nil
}

// hashAuditTarget is how a target is recorded in the audit trail: a digest,
// so the trail shows repeat asks without storing the targets asked about.
func hashAuditTarget(v string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(v))))
	return "sha256:" + hex.EncodeToString(sum[:16])
}
