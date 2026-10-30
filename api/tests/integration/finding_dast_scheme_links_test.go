package integration

// Same-issue links between the http and https views of one page: the same
// DAST check at the same host, path and parameter names on one asset, found
// over http and over https, stays two findings (another origin, port and
// transport) linked as one issue. The earlier finding is the original; the
// link changes no status; the second view raises no second "new finding"
// notification and the dashboard counts the page once. Another port,
// another path, another tenant and a person's unlink are never linked.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func nucleiPage(rule, url string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "Template " + rule, Severity: ctis.SeverityHigh,
		RuleID: rule, Location: &ctis.FindingLocation{Path: url}}
}

func (v *vaRig) schemeLinks(t *testing.T, tn vaTenant) int {
	t.Helper()
	return v.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1 AND state = 'active' AND rule = 'dast_scheme'`, tn.tenant.String())
}

func (v *vaRig) idOfURL(t *testing.T, tn vaTenant, rule, url string) string {
	t.Helper()
	var id string
	require.NoError(t, v.r.db.QueryRow(`SELECT id FROM findings WHERE tenant_id = $1 AND rule_id = $2 AND identity_key->'fields' @> jsonb_build_array(jsonb_build_object('n', 'url', 'v', $3::text))`,
		tn.tenant.String(), rule, url).Scan(&id), url)
	return id
}

func TestDASTSchemeLinks_HTTPAndHTTPSOfOnePage(t *testing.T) {
	v := newVARig(t, true)
	tn := v.tenant(t, "ds1-"+shared.NewID().String()[:8]+".example.com")
	const rule = "wordpress-click2shell"
	https, http := "https://"+tn.host+"/wp-admin/install.php", "http://"+tn.host+"/wp-admin/install.php"

	v.scan(t, tn, "nuclei", nucleiPage(rule, https))
	notified := v.notifiedCount("nuclei")
	v.scan(t, tn, "nuclei", nucleiPage(rule, http))
	sID, hID := v.idOfURL(t, tn, rule, https), v.idOfURL(t, tn, rule, http)
	require.NotEqual(t, sID, hID, "each scheme stays its own finding")

	require.Equal(t, 1, v.schemeLinks(t, tn))
	require.Equal(t, 1, v.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1 AND state = 'active' AND rule = 'dast_scheme'
		AND primary_id = $2 AND member_id = $3 AND basis = '{asset,rule,method,url,params}'`, tn.tenant.String(), sID, hID),
		"the earlier (https) finding is the original")
	require.Equal(t, 2, v.count(t, `SELECT count(*) FROM findings WHERE id IN ($1, $2) AND status = 'new' AND duplicate_of IS NULL`, sID, hID),
		"a link changes no status")
	require.Equal(t, notified, v.notifiedCount("nuclei"), "the second view of an open page raised a second notification")

	// The dashboard facts count the page once.
	_, err := v.r.db.Exec(`SELECT dash_recompute_asset($1, $2)`, tn.tenant.String(), tn.asset.String())
	require.NoError(t, err)
	require.Equal(t, 1, v.count(t, `SELECT COALESCE(sum(finding_count), 0) FROM dash_asset_state WHERE tenant_id = $1 AND asset_id = $2 AND severity = 'high' AND lens = 'open'`,
		tn.tenant.String(), tn.asset.String()))

	// A later sighting of both changes nothing.
	v.scan(t, tn, "nuclei", nucleiPage(rule, https), nucleiPage(rule, http))
	require.Equal(t, 1, v.schemeLinks(t, tn))

	// A person's unlink sticks across sightings.
	_, _, err = v.repo.Unlink(context.Background(), tn.tenant, shared.MustIDFromString(sID), shared.MustIDFromString(hID), "")
	require.NoError(t, err)
	v.scan(t, tn, "nuclei", nucleiPage(rule, https), nucleiPage(rule, http))
	require.Equal(t, 0, v.schemeLinks(t, tn), "an unlinked pair was linked again")
}

func TestDASTSchemeLinks_Refusals(t *testing.T) {
	v := newVARig(t, true)
	tn := v.tenant(t, "ds2-"+shared.NewID().String()[:8]+".example.com")

	// Another port is another service, not the other scheme of one page.
	v.scan(t, tn, "nuclei", nucleiPage("panel-a", "https://"+tn.host+":8443/admin"), nucleiPage("panel-a", "http://"+tn.host+":8443/admin"))
	// Another path, and another template, are other checks.
	v.scan(t, tn, "nuclei", nucleiPage("panel-b", "https://"+tn.host+"/a"), nucleiPage("panel-b", "http://"+tn.host+"/b"))
	v.scan(t, tn, "nuclei", nucleiPage("panel-c", "https://"+tn.host+"/c"), nucleiPage("panel-d", "http://"+tn.host+"/c"))
	require.Equal(t, 0, v.schemeLinks(t, tn))

	// The same host name in another tenant: each tenant holds one scheme,
	// never a cross-tenant pair.
	other := v.tenant(t, tn.host)
	v.scan(t, tn, "nuclei", nucleiPage("panel-e", "https://"+tn.host+"/e"))
	v.scan(t, other, "nuclei", nucleiPage("panel-e", "http://"+tn.host+"/e"))
	require.Equal(t, 0, v.schemeLinks(t, tn))
	require.Equal(t, 0, v.schemeLinks(t, other))
	require.Equal(t, 0, v.count(t, `SELECT count(*) FROM finding_issue_links l JOIN findings p ON p.id = l.primary_id JOIN findings m ON m.id = l.member_id
		WHERE p.tenant_id <> m.tenant_id`))
}

func TestDASTSchemeLinks_UnwiredLinksNothing(t *testing.T) {
	v := newVARig(t, false)
	tn := v.tenant(t, "ds3-"+shared.NewID().String()[:8]+".example.com")
	v.scan(t, tn, "nuclei", nucleiPage("panel-f", "https://"+tn.host+"/f"), nucleiPage("panel-f", "http://"+tn.host+"/f"))
	require.Equal(t, 0, v.schemeLinks(t, tn))
}
