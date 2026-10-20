package integration

// A secret's rotation group and finding identity come only from the keyed
// hash of its raw value, never from a mask: every short secret masks to the
// same word and every AWS key to the same prefix (research 214 D-1, D-2).

import (
	"testing"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func secretFindingAt(rule, path string, line int, value string, raw ...string) ctis.Finding {
	f := secretFinding(rule, path, value, raw...)
	f.Location.StartLine = line
	return f
}

func TestRotateKey_DifferentSecretsNeverShareAGroup(t *testing.T) {
	r, svc, _ := newKeyIngest(t)
	tn := r.newTenant()

	// Two AWS keys and two short passwords with no raw hash: masks collide.
	ingestFindings(t, svc, tn, "betterleaks",
		secretFinding("aws-1", "config/a.env", "AKIA********"),
		secretFinding("aws-2", "config/b.env", "AKIA********"),
		secretFinding("pw-1", "app/a.py", "REDACTED"),
		secretFinding("pw-2", "app/b.py", "REDACTED"))
	keys := remediationKeys(t, r, tn.tenant)
	for _, rule := range []string{"aws-1", "aws-2", "pw-1", "pw-2"} {
		if k, ok := keys[rule]; ok {
			assert.NotRegexp(t, `^rotate:secret:`, k.key, "%s has no raw hash, so no shared rotation group", rule)
		}
	}

	// With the raw hash: same secret shares a group, different ones do not.
	ingestFindings(t, svc, tn, "betterleaks",
		secretFinding("h-aws-1", "config/c.env", "AKIA********", "AKIAIOSFODNN7EXAMPLE"),
		secretFinding("h-aws-2", "config/d.env", "AKIA********", "AKIAZZZZZZZZ99999999"),
		secretFinding("h-aws-1b", "config/e.env", "AKIA********", "AKIAIOSFODNN7EXAMPLE"))
	keys = remediationKeys(t, r, tn.tenant)
	assert.Regexp(t, `^rotate:secret:[0-9a-f]+$`, keys["h-aws-1"].key)
	assert.NotEqual(t, keys["h-aws-1"].key, keys["h-aws-2"].key)
	assert.Equal(t, keys["h-aws-1"].key, keys["h-aws-1b"].key)
}

func TestRotateKey_SameSecretInTwoTenantsNeverShares(t *testing.T) {
	r, svc, _ := newKeyIngest(t)
	a, b := r.newTenant(), r.newTenant()
	ingestFindings(t, svc, a, "betterleaks", secretFinding("x", "c.env", "AKIA********", "AKIAIOSFODNN7EXAMPLE"))
	ingestFindings(t, svc, b, "betterleaks", secretFinding("x", "c.env", "AKIA********", "AKIAIOSFODNN7EXAMPLE"))
	ka, kb := remediationKeys(t, r, a.tenant)["x"].key, remediationKeys(t, r, b.tenant)["x"].key
	require.Regexp(t, `^rotate:secret:`, ka)
	assert.NotEqual(t, ka, kb)
}

func TestDedupSecrets_TwoShortPasswordsSameFileAreTwoFindings(t *testing.T) {
	r, svc, _ := newKeyIngest(t)
	tn := r.newTenant()
	ingestFindings(t, svc, tn, "betterleaks",
		secretFindingAt("pw", "app/settings.py", 10, "REDACTED"),
		secretFindingAt("pw", "app/settings.py", 20, "REDACTED"))
	var n int
	require.NoError(t, r.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND finding_type = 'secret'
		AND status <> 'duplicate'`, tn.tenant.String()).Scan(&n))
	assert.Equal(t, 2, n)
	// A rescan of the same two stays two.
	ingestFindings(t, svc, tn, "betterleaks",
		secretFindingAt("pw", "app/settings.py", 10, "REDACTED"),
		secretFindingAt("pw", "app/settings.py", 20, "REDACTED"))
	require.NoError(t, r.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND finding_type = 'secret'
		AND status <> 'duplicate'`, tn.tenant.String()).Scan(&n))
	assert.Equal(t, 2, n)
}
