package campaignaccess

import (
	"regexp"
	"strings"
	"testing"
)

// Registries reuse each other's templates by rewriting a short alias
// (the asset list's "a." becomes "assets."); the team SQL must survive it.
func TestSQLSurvivesAliasRebase(t *testing.T) {
	bareA := regexp.MustCompile(`\ba\.`)
	for name, q := range map[string]string{
		"member":  MemberCampaignsSQL("$1", "$2"),
		"roles":   MemberCampaignsWithRolesSQL("$1", "$2", "$3"),
		"role":    RoleSQL("$1", "f.pentest_campaign_id", "$2"),
		"visible": FindingVisibleSQL("f.pentest_campaign_id", "f.status", "$1", "$2"),
	} {
		if bareA.MatchString(q) {
			t.Errorf("%s uses the alias a., which other registries rewrite: %s", name, q)
		}
		if !strings.Contains(q, View) {
			t.Errorf("%s does not read %s: %s", name, View, q)
		}
	}
}

// The visibility subqueries never refer to the finding (a reference made
// the database re-run the team lookup per finding), and a client sees only
// published findings.
func TestFindingVisibleSQL_Shape(t *testing.T) {
	q := FindingVisibleSQL("f.pentest_campaign_id", "f.status", "$1", "$2")
	for _, sub := range regexp.MustCompile(`ARRAY\(([^()]*)\)`).FindAllStringSubmatch(q, -1) {
		if strings.Contains(sub[1], "f.") {
			t.Errorf("subquery refers to the finding: %s", sub[1])
		}
	}
	for _, need := range []string{"pca.role <> 'client'", "f.status NOT IN ('draft', 'in_review')", "pca.tenant_id = $1", "pca.user_id = $2"} {
		if !strings.Contains(q, need) {
			t.Errorf("missing %q in %s", need, q)
		}
	}
}
