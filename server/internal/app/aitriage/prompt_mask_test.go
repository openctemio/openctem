package aitriage

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/server/internal/app/aibundle"
	"github.com/openctemio/openctem/server/internal/app/aipolicy"
	"github.com/openctemio/openctem/server/internal/infra/llm"
	"github.com/openctemio/openctem/server/pkg/aimask"
	aitriagedom "github.com/openctemio/openctem/server/pkg/domain/aitriage"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// echoLLM answers with the placeholders it was given, the way a model refers
// to a host or an address it only saw masked.
type echoLLM struct {
	mu     sync.Mutex
	prompt string
	calls  int
	extra  string // appended to the summary (e.g. an invented placeholder)
}

var (
	ipTokenRE    = regexp.MustCompile(`IP_PRIV_[A-Z2-7]+`)
	emailTokenRE = regexp.MustCompile(`EMAIL_[A-Z2-7]+`)
	hostTokenRE  = regexp.MustCompile(`DOMAIN_[A-Z2-7]+`)
)

func (e *echoLLM) Complete(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	e.prompt = req.UserPrompt
	ip, mail, host := ipTokenRE.FindString(req.UserPrompt), emailTokenRE.FindString(req.UserPrompt), hostTokenRE.FindString(req.UserPrompt)
	summary := "Restrict " + ip + " and tell " + mail + " about db01." + host + e.extra
	content := `{"severity_assessment":"high","severity_justification":"reachable on ` + ip + `","risk_score":50,
"exploitability":"medium","exploitability_details":"d","business_impact":"b","false_positive_likelihood":0.1,
"false_positive_reason":"","priority_rank":50,"remediation_steps":[{"step":1,"description":"Firewall ` + ip + `","effort":"low"}],
"related_cves":[],"related_cwes":[],"summary":"` + summary + `"}`
	return &llm.CompletionResponse{Content: content, PromptTokens: 10, CompletionTokens: 10, TotalTokens: 20}, nil
}
func (e *echoLLM) Name() string    { return "echo" }
func (e *echoLLM) Model() string   { return "echo-model" }
func (e *echoLLM) Validate() error { return nil }

// fakeMaskingInputs returns the organization's policy and seeded names.
type fakeMaskingInputs struct {
	policy  aimask.Policy
	org     string
	err     error
	tenants []shared.ID
}

func (f *fakeMaskingInputs) BundleInput(_ context.Context, tenantID shared.ID, fd *vulnerability.Finding, ceiling aipolicy.Class, key []byte) (aibundle.Input, error) {
	f.tenants = append(f.tenants, tenantID)
	if f.err != nil {
		return aibundle.Input{}, f.err
	}
	return aibundle.Input{TenantID: tenantID, Finding: fd, Ceiling: ceiling, Policy: f.policy, RunKey: key, OrgNames: []string{f.org}}, nil
}

const (
	maskHost  = "db01.payroll.example.com"
	maskIP    = "10.20.30.40"
	maskEmail = "alice.admin@example.com"
	maskOrg   = "Globex Payroll"
)

func maskHarness(t *testing.T, mi *fakeMaskingInputs) (*egressHarness, *echoLLM, *vulnerability.Finding, *aitriagedom.TriageResult) {
	t.Helper()
	h := newEgressHarness(t)
	e := &echoLLM{}
	h.svc.llmFactory = fakeFactory{p: e}
	if mi != nil {
		h.svc.SetMaskingInputs(mi)
	}
	f := h.finding(t, vulnerability.FindingSourceDAST, nil)
	f.SetTitle("Open admin panel on " + maskHost)
	f.SetDescription("The " + maskOrg + " panel at https://" + maskHost + "/users/12345?session=abc answers on " +
		maskIP + "; " + maskIP + " is reachable. Owner " + maskEmail + ".")
	return h, e, f, h.pendingRow(t, f)
}

// Hosts, addresses, e-mail addresses, URL ids and the organization's name
// never reach the provider; the same value is one placeholder within the
// request; the stored analysis carries the real values again.
func TestAITriage_PromptMaskedAndAnswerUnmasked(t *testing.T) {
	mi := &fakeMaskingInputs{policy: aimask.FullPolicy(), org: maskOrg}
	h, e, f, row := maskHarness(t, mi)

	require.NoError(t, h.svc.ProcessTriage(context.Background(), row.ID(), h.tenantID, f.ID()))
	require.Equal(t, 1, e.calls)
	require.Equal(t, []shared.ID{h.tenantID}, mi.tenants, "the policy is read for the finding's own organization")

	for _, raw := range []string{maskHost, "example.com", maskIP, maskEmail, maskOrg, "12345", "session=abc"} {
		require.NotContains(t, e.prompt, raw, "the provider must not see %q", raw)
	}
	fields, _, _ := strings.Cut(e.prompt, "## Platform facts")
	ips := ipTokenRE.FindAllString(fields, -1)
	require.Len(t, ips, 2)
	require.Equal(t, ips[0], ips[1], "same value, same placeholder within one request")
	require.Contains(t, e.prompt, "Platform facts (trusted)")

	require.Equal(t, aitriagedom.TriageStatusCompleted, row.Status())
	require.Contains(t, row.AnalysisSummary(), maskIP)
	require.Contains(t, row.AnalysisSummary(), maskEmail)
	require.Contains(t, row.AnalysisSummary(), "db01.example.com", "a masked domain resolves back")
	require.Contains(t, row.SeverityJustification(), maskIP)
	require.Contains(t, row.RemediationSteps()[0].Description, maskIP)
	require.Contains(t, row.RawResponse()["summary"], maskIP, "the stored raw response is unmasked too")
	for _, s := range []string{row.AnalysisSummary(), row.SeverityJustification()} {
		require.NotRegexp(t, `(IP_PRIV|EMAIL|DOMAIN)_[A-Z2-7]+`, s, "no placeholder reaches storage")
	}
	require.False(t, row.NeedsReview())
}

// Without the masking service wired every class is masked (the default).
func TestAITriage_PromptMaskedByDefault(t *testing.T) {
	h, e, f, row := maskHarness(t, nil)
	require.NoError(t, h.svc.ProcessTriage(context.Background(), row.ID(), h.tenantID, f.ID()))
	for _, raw := range []string{maskHost, maskIP, maskEmail} {
		require.NotContains(t, e.prompt, raw)
	}
	require.Contains(t, row.AnalysisSummary(), maskIP)
}

// A class the organization left readable is sent as written; the others stay
// masked.
func TestAITriage_PromptFollowsOrganizationPolicy(t *testing.T) {
	p := aimask.FullPolicy()
	p.IPs = false
	h, e, f, row := maskHarness(t, &fakeMaskingInputs{policy: p, org: maskOrg})
	require.NoError(t, h.svc.ProcessTriage(context.Background(), row.ID(), h.tenantID, f.ID()))
	require.Contains(t, e.prompt, maskIP, "addresses left readable by the organization")
	require.NotContains(t, e.prompt, maskHost)
	require.NotContains(t, e.prompt, maskEmail)
	require.Equal(t, aitriagedom.TriageStatusCompleted, row.Status())
}

// A placeholder the request never issued is not resolved and makes the result
// need a person's review.
func TestAITriage_UnknownPlaceholderNeedsReview(t *testing.T) {
	h, e, f, row := maskHarness(t, &fakeMaskingInputs{policy: aimask.FullPolicy(), org: maskOrg})
	e.extra = " and HOST_ZZ9ZZZ"
	require.NoError(t, h.svc.ProcessTriage(context.Background(), row.ID(), h.tenantID, f.ID()))
	require.Contains(t, row.AnalysisSummary(), "HOST_ZZ9ZZZ")
	require.True(t, row.NeedsReview())
	require.Contains(t, strings.Join(row.ValidationWarnings(), "\n"), unknownPlaceholderWarning)
}

// When the policy or the seeded names cannot be read nothing is sent.
func TestAITriage_MaskingUnavailableFailsClosed(t *testing.T) {
	h, e, f, row := maskHarness(t, &fakeMaskingInputs{err: errors.New("db down")})
	err := h.svc.ProcessTriage(context.Background(), row.ID(), h.tenantID, f.ID())
	require.Error(t, err)
	require.Zero(t, e.calls, "the provider must not be called without masking")
}
