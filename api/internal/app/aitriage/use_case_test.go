package aitriage

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// fakeUseCases answers one setting for every organization and use case.
type fakeUseCases struct {
	set aidom.UseCaseSetting
	err error
}

func (f fakeUseCases) UseCaseSetting(context.Context, shared.ID, aidom.UseCase) (aidom.UseCaseSetting, error) {
	return f.set, f.err
}

func autoApply() aidom.UseCaseSetting {
	s := aidom.DefaultUseCaseSetting()
	s.Mode = aidom.UseCaseAutoApply
	return s
}

func withMode(m aidom.UseCaseMode, c aidom.DataClass) aidom.UseCaseSetting {
	s := aidom.DefaultUseCaseSetting()
	s.Mode, s.Ceiling = m, c
	return s
}

// The triage use case turned off refuses every path: a person's request,
// bulk, automatic triage, and a row already queued is failed by the worker
// before any call to the model.
func TestAITriage_UseCaseOff_RefusesEveryPath(t *testing.T) {
	ctx := context.Background()
	h := newEgressHarness(t)
	h.svc.SetUseCases(fakeUseCases{set: withMode(aidom.UseCaseOff, aidom.DataClassInternal)})
	f := h.finding(t, vulnerability.FindingSourceDAST, nil)
	user := shared.NewID().String()
	tid := h.tenantID.String()

	_, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: tid, FindingID: f.ID().String(), TriageType: "manual", UserID: &user})
	require.ErrorIs(t, err, ErrUseCaseOff)

	_, err = h.svc.RequestBulkTriage(ctx, BulkTriageRequest{TenantID: tid, FindingIDs: []string{f.ID().String()}, UserID: &user})
	require.ErrorIs(t, err, ErrUseCaseOff)

	h.ai.s.AutoTriageEnabled, h.ai.s.AutoTriageSeverities = true, []string{"high"}
	ok, err := h.svc.ShouldAutoTriage(ctx, h.tenantID, "high")
	require.NoError(t, err)
	require.False(t, ok, "no automatic triage while the use case is off")

	row := h.pendingRow(t, f)
	err = h.svc.ProcessTriage(ctx, row.ID(), h.tenantID, f.ID())
	require.ErrorIs(t, err, aitriagedom.ErrTriageFailed)
	require.Equal(t, FailUseCaseOff, row.ErrorMessage())
	require.Zero(t, h.llm.calls, "the model must never be called for a use case that is off")
}

// An unreadable use case setting fails closed: the request is refused and
// the worker sends nothing.
func TestAITriage_UseCaseUnreadable_FailsClosed(t *testing.T) {
	ctx := context.Background()
	h := newEgressHarness(t)
	h.svc.SetUseCases(fakeUseCases{err: errors.New("db down")})
	f := h.finding(t, vulnerability.FindingSourceDAST, nil)
	user := shared.NewID().String()
	_, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: h.tenantID.String(), FindingID: f.ID().String(), TriageType: "manual", UserID: &user})
	require.Error(t, err)

	row := h.pendingRow(t, f)
	_ = h.svc.ProcessTriage(ctx, row.ID(), h.tenantID, f.ID())
	require.Zero(t, h.llm.calls)
}

// The data class ceiling decides which fields reach the model: the snippet
// only under restricted, the finding's own text only from internal, and
// public sends only public ids. A secret finding never sends its snippet.
func TestAITriage_UseCaseCeiling_FiltersThePrompt(t *testing.T) {
	ctx := context.Background()
	const snippet = "password = load_from_vault()"
	run := func(t *testing.T, ceiling aidom.DataClass, src vulnerability.FindingSource, cve string) (string, *aitriagedom.TriageResult) {
		h := newEgressHarness(t)
		h.svc.SetUseCases(fakeUseCases{set: withMode(aidom.UseCaseSuggest, ceiling)})
		f := h.finding(t, src, nil)
		f.SetSnippet(snippet)
		if cve != "" {
			require.NoError(t, f.SetClassification(cve, nil, "", []string{"CWE-89"}, nil))
		}
		row := h.pendingRow(t, f)
		_ = h.svc.ProcessTriage(ctx, row.ID(), h.tenantID, f.ID())
		return h.llm.last.UserPrompt, row
	}

	p, _ := run(t, aidom.DataClassRestricted, vulnerability.FindingSourceSAST, "")
	require.Contains(t, p, snippet)
	require.Contains(t, p, "SQL injection in the login form")

	p, _ = run(t, aidom.DataClassInternal, vulnerability.FindingSourceSAST, "")
	require.NotContains(t, p, snippet, "the snippet is restricted: withheld under internal")
	require.Contains(t, p, "SQL injection in the login form")

	p, _ = run(t, aidom.DataClassPublic, vulnerability.FindingSourceSAST, "CVE-2024-0001")
	require.NotContains(t, p, "SQL injection in the login form", "the title is internal: withheld under public")
	require.NotContains(t, p, snippet)
	require.Contains(t, p, "CVE-2024-0001")

	p, row := run(t, aidom.DataClassPublic, vulnerability.FindingSourceSAST, "")
	require.Empty(t, p, "nothing public to send: no call")
	require.Equal(t, FailNothingToSend, row.ErrorMessage())

	p, _ = run(t, aidom.DataClassRestricted, vulnerability.FindingSourceSecret, "")
	require.NotContains(t, p, snippet, "a secret finding never sends its snippet")
}
