package integration

// What a secret finding stores and shows: the producer's preview and its
// masked source line are kept, a raw line is replaced by a placeholder, and a
// later scan replaces a preview that tells nothing (research 214 P0-5).

import (
	"testing"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func secretWithLine(rule, snippet, preview string, length int) ctis.Finding {
	f := secretFinding(rule, "app/settings.py", preview)
	f.Location.Snippet = snippet
	f.Secret.Length = length
	return f
}

type storedSecret struct{ snippet, preview string }

func storedSecrets(t *testing.T, r *v2Rig, tenant string) map[string]storedSecret {
	t.Helper()
	rows, err := r.db.Query(`SELECT rule_id, COALESCE(snippet, ''), COALESCE(type_details->'secret'->>'masked_preview', '')
		FROM findings WHERE tenant_id = $1 AND finding_type = 'secret'`, tenant)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]storedSecret{}
	for rows.Next() {
		var rule string
		var s storedSecret
		require.NoError(t, rows.Scan(&rule, &s.snippet, &s.preview))
		out[rule] = s
	}
	require.NoError(t, rows.Err())
	return out
}

func TestSecretFinding_KeepsMaskedLineAndProducerPreview(t *testing.T) {
	r, svc, _ := newKeyIngest(t)
	tn := r.newTenant()
	ingestFindings(t, svc, tn, "betterleaks",
		secretWithLine("masked", `password = "REDACTED"`, "AKIA…MPLE", 20),
		secretWithLine("raw", `token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"`, "ghp_…6789", 40),
		secretWithLine("marker", `pw = "REDACTED"`, "REDACTED", 8))
	got := storedSecrets(t, r, tn.tenant.String())
	assert.Equal(t, storedSecret{`password = "REDACTED"`, "AKIA…MPLE"}, got["masked"], "the producer's line and preview are kept")
	assert.NotContains(t, got["raw"].snippet, "ghp_ABCDEFGHIJ", "a raw line is never stored")
	assert.NotContains(t, got["raw"].snippet, "0123456789")
	assert.Equal(t, "", got["marker"].preview, "the word REDACTED is no preview (never RE…ED)")
}

func TestSecretFinding_RescanReplacesAnUnusablePreview(t *testing.T) {
	r, svc, _ := newKeyIngest(t)
	tn := r.newTenant()
	ingestFindings(t, svc, tn, "betterleaks", secretWithLine("k", `pw = "REDACTED"`, "AKIA…MPLE", 20))
	// The stored value is what an earlier release left: RE…ED and a short line.
	_, err := r.db.Exec(`UPDATE findings SET snippet = 'RE…ED',
		type_details = jsonb_set(type_details, '{secret,masked_preview}', '"RE…ED"') WHERE tenant_id = $1`, tn.tenant.String())
	require.NoError(t, err)
	ingestFindings(t, svc, tn, "betterleaks", secretWithLine("k", `password = "REDACTED"`, "AKIA…MPLE", 20))
	assert.Equal(t, storedSecret{`password = "REDACTED"`, "AKIA…MPLE"}, storedSecrets(t, r, tn.tenant.String())["k"])
}
