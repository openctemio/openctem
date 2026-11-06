package integration

// The members of a suggestion (docs/rfcs/RFC-098-remediation-tasks.md §10)
// carry what a person needs to judge it: location, rule, CWE ids, installed
// version, the scanner's advice as capped plain text with secrets redacted
// (no fix code for a secret finding) and the task that claimed a finding
// since. A restricted member gets only their findings; another tenant gets
// not found.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func membersByID(t *testing.T, r *rsRig, ctx context.Context, id shared.ID) (map[shared.ID]remediation.SuggestionMember, int64) {
	t.Helper()
	res, err := r.sug.Members(ctx, r.tenant, id, pagination.New(1, 100))
	require.NoError(t, err)
	out := map[shared.ID]remediation.SuggestionMember{}
	for _, m := range res.Data {
		out[m.FindingID] = m
	}
	return out, res.Total
}

func TestRemediationSuggestionMembers_Detail(t *testing.T) {
	r := newAcceptRig(t)
	ctx := r.adminCtx()
	code := r.keyed(r.assetA, djangoKey, "P1")
	web := r.keyed(r.assetA, djangoKey, "P2")
	sec := r.keyed(r.assetB, djangoKey, "P2")
	r.exec(`UPDATE findings SET file_path = 'app/settings.py', start_line = 42, rule_id = 'py.django.debug', cwe_ids = '{CWE-489}',
		remediation = jsonb_build_object('recommendation', 'Upgrade django; old key AKIAABCDEFGHIJKLMNOP', 'fix_code', 'DEBUG = False')
		WHERE id = $1`, code.String())
	r.exec(`UPDATE findings SET network_port = 443, network_transport = 'tcp',
		metadata = jsonb_build_object('affected_assets', jsonb_build_array('https://shop.example.com/a','b','c','d','e','f','g'))
		WHERE id = $1`, web.String())
	r.exec(`UPDATE findings SET finding_type = 'secret', remediation = jsonb_build_object('fix_code', 'token = "s3cr3t-value"')
		WHERE id = $1`, sec.String())
	r.run()
	sg := r.list(ctx)[0]

	ms, total := membersByID(t, r, ctx, sg.ID)
	require.EqualValues(t, 3, total)
	c := ms[code]
	assert.Equal(t, "app/settings.py", c.FilePath)
	assert.Equal(t, 42, c.StartLine)
	assert.Equal(t, "py.django.debug", c.RuleID)
	assert.Equal(t, []string{"CWE-489"}, c.CWEIDs)
	assert.Equal(t, "high", c.AssetCriticality)
	assert.Equal(t, "DEBUG = False", c.FixCode)
	assert.NotContains(t, c.Recommendation, "AKIAABCDEFGHIJKLMNOP", "secret shapes are redacted")
	assert.True(t, strings.HasPrefix(c.Recommendation, "Upgrade django"))
	assert.Nil(t, c.ActiveTask)

	w := ms[web]
	assert.Equal(t, 443, w.NetworkPort)
	assert.Len(t, w.LocationTargets, remediation.MaxMemberTargets, "targets are capped")
	assert.Equal(t, "https://shop.example.com/a", w.LocationTargets[0])

	assert.Empty(t, ms[sec].FixCode, "a secret finding never carries its fix code")

	// A task claims a finding after the suggestion was made.
	task, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "By hand",
		FindingIDs: []shared.ID{web}}, auditapp.AuditContext{})
	require.NoError(t, err)
	ms, _ = membersByID(t, r, ctx, sg.ID)
	require.NotNil(t, ms[web].ActiveTask)
	assert.Equal(t, task.ID, ms[web].ActiveTask.ID)
	assert.Equal(t, "By hand", ms[web].ActiveTask.Title)
}

func TestRemediationSuggestionMembers_ScopeAndTenant(t *testing.T) {
	r := newAcceptRig(t)
	a1 := r.keyed(r.assetA, djangoKey, "P1")
	r.keyed(r.assetB, djangoKey, "P1")
	r.keyed(r.assetB, djangoKey, "P2")
	r.run()
	sg := r.list(r.adminCtx())[0]

	ms, total := membersByID(t, r, r.memberCtx(), sg.ID)
	assert.EqualValues(t, 1, total, "only the member's findings")
	assert.Contains(t, ms, a1)
	got, err := r.sug.Get(r.memberCtx(), r.tenant, sg.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, got.HiddenMembers, "the others are a count")

	_, err = r.sug.Members(r.adminCtx(), r.other, sg.ID, pagination.New(1, 50))
	assert.ErrorIs(t, err, shared.ErrNotFound, "another tenant: not found")
}
