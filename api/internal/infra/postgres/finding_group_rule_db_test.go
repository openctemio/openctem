package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Grouping by rule makes issues without a CVE visible as one issue: the same
// nuclei template on several hosts, the same secret rule in several repos.
// Before RFC-044 P0 the only issue-level grouping was by CVE, which drops
// every finding without one, and group_by=rule_id answered an error.
func TestListFindingGroups_ByRule_DB(t *testing.T) {
	db := openGroupsDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, db)
	hosts := []shared.ID{
		seedOwnedAsset(ctx, t, db, tenantID, nil),
		seedOwnedAsset(ctx, t, db, tenantID, nil),
		seedOwnedAsset(ctx, t, db, tenantID, nil),
	}

	seed := func(asset shared.ID, tool, rule, ruleName, title, severity, status, source, cve string) {
		t.Helper()
		var cveArg, ruleArg, nameArg any
		if cve != "" {
			cveArg = cve
		}
		if rule != "" {
			ruleArg = rule
		}
		if ruleName != "" {
			nameArg = ruleName
		}
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, rule_name, title, message,
				severity, status, fingerprint, cve_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'm', $9, $10, $11, $12)`,
			id.String(), tenantID.String(), asset.String(), source, tool, ruleArg, nameArg, title,
			severity, status, "rule-fp-"+id.String(), cveArg); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	// One exposure template on three hosts (one already resolved), mixed tool-name case.
	seed(hosts[0], "nuclei", "exposed-git-config", "", "Exposed .git/config", "medium", "new", "dast", "")
	seed(hosts[1], "Nuclei", "exposed-git-config", "", "Exposed .git/config", "high", "confirmed", "dast", "")
	seed(hosts[2], "nuclei", "exposed-git-config", "", "Exposed .git/config", "medium", "resolved", "dast", "")
	// A secret rule twice on one repo.
	seed(hosts[0], "betterleaks", "github-pat", "GitHub Personal Access Token", "Secret: github-pat", "high", "new", "secret", "")
	seed(hosts[0], "betterleaks", "github-pat", "", "Secret: github-pat", "high", "new", "secret", "")
	// A CVE template keeps its CVE count.
	seed(hosts[1], "nuclei", "CVE-2021-44228", "", "Log4Shell", "critical", "new", "dast", "CVE-2021-44228")
	// No rule: not grouped. Pentest: excluded like every other grouping.
	seed(hosts[1], "manual", "", "", "No rule", "critical", "new", "manual", "")
	seed(hosts[2], "pentest", "PT-1", "", "Pentest issue", "critical", "new", "pentest", "")

	res, err := NewFindingRepository(&DB{DB: db}).ListFindingGroups(ctx, tenantID, "rule_id",
		vulnerability.FindingFilter{}, pagination.New(1, 50))
	if err != nil {
		t.Fatalf("ListFindingGroups(rule_id): %v", err)
	}
	if res.Total != 3 || len(res.Data) != 3 {
		t.Fatalf("got %d groups (total %d), want 3: %+v", len(res.Data), res.Total, res.Data)
	}
	byKey := map[string]*vulnerability.FindingGroup{}
	for _, g := range res.Data {
		byKey[g.GroupKey] = g
		if g.GroupType != "rule" {
			t.Errorf("%s: group_type %q, want rule", g.GroupKey, g.GroupType)
		}
	}

	// Worst severity first.
	if res.Data[0].GroupKey != "CVE-2021-44228" {
		t.Errorf("first group %q, want the critical one", res.Data[0].GroupKey)
	}

	tpl := byKey["exposed-git-config"]
	if tpl == nil {
		t.Fatal("template group missing")
	}
	if tpl.Stats.Total != 3 || tpl.Stats.AffectedAssets != 3 || tpl.Stats.Resolved != 1 || tpl.Stats.Open != 2 {
		t.Errorf("template stats %+v, want total 3, assets 3, open 2, resolved 1", tpl.Stats)
	}
	if tpl.Severity != "high" || tpl.Label != "Exposed .git/config" {
		t.Errorf("template severity %q label %q", tpl.Severity, tpl.Label)
	}
	if tools, _ := tpl.Metadata["tools"].([]string); len(tools) != 1 || tools[0] != "nuclei" {
		t.Errorf("template tools %v, want [nuclei] (case folded)", tpl.Metadata["tools"])
	}

	pat := byKey["github-pat"]
	if pat == nil || pat.Stats.Total != 2 || pat.Stats.AffectedAssets != 1 {
		t.Fatalf("secret rule group %+v, want 2 findings on 1 asset", pat)
	}
	if pat.Label != "GitHub Personal Access Token" {
		t.Errorf("secret rule label %q, want the stored rule name", pat.Label)
	}
	if byKey["CVE-2021-44228"].Metadata["cve_count"] != 1 {
		t.Errorf("cve_count %v, want 1", byKey["CVE-2021-44228"].Metadata["cve_count"])
	}
}
