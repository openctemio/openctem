package integration

// Honest remediation grouping (RFC-015): a scanner's boilerplate advice never
// groups findings of different vulnerabilities, keys derived by older key
// rules are derived again before the suggestion generator uses them, and a
// suggestion's confidence states the factors behind it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func codeFinding(rule, title, path string, line int) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: title, Severity: ctis.SeverityHigh,
		RuleID: rule, Location: &ctis.FindingLocation{Path: path, StartLine: line},
		Remediation: &ctis.Remediation{Recommendation: "Apply the suggested fix code.", FixCode: "user.check_password(pw)", FixAvailable: true}}
}

func hostFinding(rule, title, solution string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: title, Severity: ctis.SeverityCritical,
		RuleID: rule, Remediation: &ctis.Remediation{Recommendation: solution}}
}

func TestRemediationGrouping_BoilerplateAndStaleKeys(t *testing.T) {
	r, svc, applier := newKeyIngest(t)
	tn := r.newTenant()
	ctx := context.Background()

	// One "Missing user" and two "Unvalidated password" findings that the
	// code scanner gave the same boilerplate advice, and two host findings
	// that one specific upgrade fixes.
	ingestFindings(t, svc, tn, "opengrep",
		codeFinding("py.missing-user", "Missing User", "app/auth.py", 12),
		codeFinding("py.unvalidated-password", "Unvalidated Password", "app/auth.py", 40),
		codeFinding("py.unvalidated-password", "Unvalidated Password", "app/admin.py", 7))
	ingestFindings(t, svc, tn, "nessus",
		hostFinding("p-1001", "Jenkins RCE", "Upgrade Jenkins to 2.442 or later."),
		hostFinding("p-1002", "Jenkins XSS", "Upgrade Jenkins to 2.442 or later.\nRestart the service afterwards."))

	keys := remediationKeys(t, r, tn.tenant)
	assert.NotContains(t, keys, "py.missing-user", "boilerplate advice must not give a key")
	assert.NotContains(t, keys, "py.unvalidated-password")
	require.Contains(t, keys, "p-1001")
	assert.Equal(t, keys["p-1001"].key, keys["p-1002"].key, "one specific fix groups across plugins")
	assert.Equal(t, "Upgrade Jenkins to 2.442 or later.", keys["p-1001"].title)

	// Simulate keys left by the first key rules: the boilerplate text hashed
	// into one "sol:<sha256>" key for all three code findings, version 1.
	sum := sha256.Sum256([]byte("apply the suggested fix code."))
	legacy := "sol:" + hex.EncodeToString(sum[:])
	_, err := r.db.Exec(`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title, algorithm_version)
		SELECT id, tenant_id, $2, 'Apply the suggested fix code.', 1 FROM findings WHERE tenant_id = $1 AND rule_id LIKE 'py.%'`,
		tn.tenant.String(), legacy)
	require.NoError(t, err)

	db := &postgres.DB{DB: r.db}
	sug := remediationapp.NewSuggestionService(postgres.NewRemediationSuggestionRepository(db), logger.NewNop())

	// Without the re-derivation, stale keys are never trusted.
	_, err = sug.RunTenant(ctx, tn.tenant)
	require.NoError(t, err)
	assertNoSuggestionFor(t, r, tn.tenant.String(), legacy)

	// With it, the run derives the keys again: the legacy rows go away.
	sug.SetKeyRederiver(applier)
	_, err = sug.RunTenant(ctx, tn.tenant)
	require.NoError(t, err)
	var stale int
	require.NoError(t, r.db.QueryRow(`SELECT COUNT(*) FROM finding_remediation_keys WHERE tenant_id = $1 AND algorithm_version < $2`,
		tn.tenant.String(), remediation.KeyAlgorithmVersion).Scan(&stale))
	assert.Zero(t, stale)
	assert.NotContains(t, remediationKeys(t, r, tn.tenant), "py.missing-user")
	assertNoSuggestionFor(t, r, tn.tenant.String(), legacy)

	// The host group is proposed with an honest confidence and its basis:
	// one solution, two plugins, two titles.
	var (
		conf  float64
		basis string
		title string
	)
	require.NoError(t, r.db.QueryRow(`SELECT confidence, fix_spec->>'basis', title FROM remediation_suggestions
		WHERE tenant_id = $1 AND action_key = $2 AND state = 'proposed'`, tn.tenant.String(), keys["p-1001"].key).Scan(&conf, &basis, &title))
	assert.InDelta(t, 0.6, conf, 0.001)
	assert.JSONEq(t, `["same_specific_solution_text"]`, basis)
	assert.Equal(t, "Upgrade Jenkins to 2.442 or later.", title)
}

func assertNoSuggestionFor(t *testing.T, r *v2Rig, tenant, key string) {
	t.Helper()
	var n int
	require.NoError(t, r.db.QueryRow(`SELECT COUNT(*) FROM remediation_suggestions WHERE tenant_id = $1 AND action_key = $2
		AND state IN ('proposed', 'snoozed')`, tenant, key).Scan(&n))
	assert.Zero(t, n, "no open suggestion may use key %s", key)
}
