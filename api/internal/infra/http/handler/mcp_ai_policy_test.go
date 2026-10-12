package handler

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/compliance"
	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// fakeAIPolicy is the organization's MCP policy.
type fakeAIPolicy struct {
	maxTLP string
	err    error
}

func (f fakeAIPolicy) MCPPolicy(context.Context, shared.ID) (tenantdom.MCPSettings, error) {
	return tenantdom.MCPSettings{MaxTLP: f.maxTLP}, f.err
}

func campaignAt(t *testing.T, tlp pentestdom.TLP, aiOff bool) *pentestdom.Campaign {
	t.Helper()
	c := newTestCampaign(t)
	c.SetProfile(nil, "", "", tlp)
	c.SetAIAssistantsDisabled(aiOff)
	return c
}

func errorCode(t *testing.T, text string) string {
	t.Helper()
	e := decodeEnvelope(t, text)
	if e.Error == nil {
		return ""
	}
	return e.Error.Code
}

// The organization's TLP limit and the lead's switch decide whether a
// campaign's content reaches an AI client; the refusal is typed.
func TestMCP_CampaignTLPGate(t *testing.T) {
	cases := []struct {
		orgMax string
		tlp    pentestdom.TLP
		aiOff  bool
		want   string // "" = allowed
	}{
		{"", pentestdom.TLPAmber, false, ""}, // default limit: amber
		{"", pentestdom.TLPClear, false, ""},
		{"", pentestdom.TLPAmberStrict, false, mcpErrCampaignRestricted},
		{"", pentestdom.TLPRed, false, mcpErrCampaignRestricted},
		{"red", pentestdom.TLPRed, false, ""},
		{"clear", pentestdom.TLPGreen, false, mcpErrCampaignRestricted},
		{"red", pentestdom.TLPClear, true, mcpErrCampaignRestricted}, // the lead's switch wins
	}
	scopes := []string{"pentest:campaigns:read", "pentest:findings:read", "pentest:retests:read"}
	for _, tc := range cases {
		pr := &fakePentestReader{campaign: campaignAt(t, tc.tlp, tc.aiOff), findings: pentestFindings(t, 1, vulnerability.SeverityHigh, vulnerability.FindingStatusConfirmed)}
		h := newTestMCPWithPentest(&fakeFindingReader{finding: pr.findings[0]}, pr)
		h.SetAIPolicy(fakeAIPolicy{maxTLP: tc.orgMax})
		for tool, args := range map[string]string{
			"get_campaign":           `{` + testCampaignArg + `}`,
			"list_campaign_findings": `{` + testCampaignArg + `}`,
			"list_retests":           `{` + testCampaignArg + `}`,
			"campaign_report_stats":  `{` + testCampaignArg + `}`,
			"get_pentest_finding":    `{"finding_id":"018f5a1e-0000-7000-8000-0000000000aa"}`,
			"get_finding":            `{"finding_id":"018f5a1e-0000-7000-8000-0000000000aa"}`,
		} {
			text, _ := callTool(t, h, "user-1", append(scopes, "findings:read"), tool, args)
			if got := errorCode(t, text); got != tc.want {
				t.Errorf("org %q campaign %s off=%v %s: code %q, want %q (%s)", tc.orgMax, tc.tlp, tc.aiOff, tool, got, tc.want, text)
			}
			if tc.want != "" && strings.Contains(text, "SQL Injection") {
				t.Errorf("%s leaked restricted content: %s", tool, text)
			}
		}
		for _, prompt := range []string{"exec_summary", "attack_narrative"} {
			body := `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"` + prompt + `","arguments":{` + testCampaignArg + `}}}`
			_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", scopes, body)
			restricted := resp.Error != nil && strings.HasPrefix(resp.Error.Message, mcpErrCampaignRestricted+":")
			if restricted != (tc.want != "") {
				t.Errorf("org %q campaign %s %s: restricted=%v (%+v)", tc.orgMax, tc.tlp, prompt, restricted, resp.Error)
			}
		}
	}
}

// Membership is checked first: a non-member gets not_found, never the
// restricted answer that would confirm the campaign exists.
func TestMCP_CampaignTLPGate_NonMemberStillNotFound(t *testing.T) {
	pr := &fakePentestReader{campaign: campaignAt(t, pentestdom.TLPRed, false), accessErr: pentestdom.ErrNotCampaignMember}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
	text, _ := callTool(t, h, "user-1", []string{"pentest:campaigns:read"}, "get_campaign", `{`+testCampaignArg+`}`)
	if code := errorCode(t, text); code != mcpErrNotFound {
		t.Fatalf("non-member: %s", text)
	}
}

// A policy that cannot be read refuses (fail closed).
func TestMCP_CampaignTLPGate_PolicyErrorFailsClosed(t *testing.T) {
	pr := &fakePentestReader{campaign: campaignAt(t, pentestdom.TLPClear, false)}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
	h.SetAIPolicy(fakeAIPolicy{err: errors.New("db down")})
	text, isErr := callTool(t, h, "user-1", []string{"pentest:campaigns:read"}, "get_campaign", `{`+testCampaignArg+`}`)
	if !isErr || strings.Contains(text, "__test campaign") || errorCode(t, text) != mcpErrInternal {
		t.Fatalf("policy error: %s", text)
	}
}

// The campaign lists ask SQL for the allowed levels only and say how many
// campaigns they left out, without naming them.
func TestMCP_ListCampaigns_LeavesOutRestricted(t *testing.T) {
	pr := &fakePentestReader{memberCampaigns: []compliance.MemberCampaign{
		memberCampaign(t, "visible", pentestdom.CampaignStatusInProgress, pentestdom.CampaignRoleLead, pentestdom.CampaignWorkCounts{}),
	}}
	h := newTestMCPWithPentest(&fakeFindingReader{}, &restrictedLister{fakePentestReader: pr, all: 3})
	h.SetAIPolicy(fakeAIPolicy{maxTLP: "green"})
	text, isErr := callTool(t, h, "user-1", []string{"pentest:campaigns:read"}, "list_campaigns", `{}`)
	if isErr {
		t.Fatal(text)
	}
	q := pr.gotCampaigns[0]
	if !slices.Equal(q.AIAllowTLP, []string{"clear", "green"}) {
		t.Fatalf("allowed levels = %v", q.AIAllowTLP)
	}
	if !strings.Contains(text, `"restricted_hidden":2`) || !strings.Contains(text, "TLP:GREEN") {
		t.Fatalf("hidden count missing: %s", text)
	}
}

// restrictedLister answers the unrestricted count with all.
type restrictedLister struct {
	*fakePentestReader
	all int64
}

func (r *restrictedLister) ListMemberCampaigns(ctx context.Context, q compliance.MemberCampaignQuery) (pagination.Result[compliance.MemberCampaign], error) {
	res, err := r.fakePentestReader.ListMemberCampaigns(ctx, q)
	if q.AIAllowTLP == nil {
		res.Total = r.all
	}
	return res, err
}

// The comment write tool refuses a finding of a restricted campaign before
// asking the person to confirm.
func TestMCP_AddFindingComment_RestrictedCampaign(t *testing.T) {
	pr := &fakePentestReader{campaign: campaignAt(t, pentestdom.TLPRed, false)}
	h := newTestMCPWithPentest(&fakeFindingReader{finding: makePentestFinding(t)}, pr)
	conf := &fakeConfirmer{approved: map[string]string{}}
	h.SetWriteTools(conf, &fakeCommenter{})
	text, isErr := resultText(wtRequest(t, h, true, []string{"findings:read", "findings:comment"},
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add_finding_comment","arguments":{"finding_id":"`+wtFinding+`","content":"note"}}}`))
	if !isErr || errorCode(t, text) != mcpErrCampaignRestricted || conf.requests != 0 {
		t.Fatalf("restricted comment: %v %s (confirmations %d)", isErr, text, conf.requests)
	}
}
