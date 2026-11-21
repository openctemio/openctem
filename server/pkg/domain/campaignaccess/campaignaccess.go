// Package campaignaccess is the one way server code asks who is on a pentest
// campaign team. The team is direct members plus the current members of
// granted user groups, each with their highest role; the database view
// pentest_campaign_access resolves it, and every reader builds its SQL with
// the helpers here instead of joining the membership tables itself.
//
// It is a leaf package (no domain imports) so that both the pentest and the
// vulnerability domains can use it.
//
// Design: docs/architecture/pentest-campaign-team.md.
package campaignaccess

import (
	"fmt"
	"strings"
)

// View is the effective-team view: one row (tenant_id, campaign_id,
// user_id, role) per person on a campaign team.
const View = "pentest_campaign_access"

// SourcesView lists each source of access (a direct membership with
// group_id NULL, or a granted group's current member).
const SourcesView = "pentest_campaign_access_sources"

// UnpublishedStatuses are the pentest finding statuses a campaign client
// never sees: the testers' work in progress.
var UnpublishedStatuses = []string{"draft", "in_review"}

// ClientRole is the read-only role of the tested organization's people.
const ClientRole = "client"

func unpublishedList() string {
	q := make([]string, len(UnpublishedStatuses))
	for i, s := range UnpublishedStatuses {
		q[i] = "'" + s + "'"
	}
	return strings.Join(q, ", ")
}

// alias names the view inside every subquery here. It must not be a short
// alias another registry rewrites (the asset registry turns "a." into
// "assets." when it reuses list fields in the query language).
const alias = "pca"

// MemberCampaignsSQL is a subquery selecting the campaign_id of every
// campaign the user is on the team of. tenantExpr and userExpr are SQL
// expressions (a placeholder such as "$1" or a column); they must never
// carry caller text.
func MemberCampaignsSQL(tenantExpr, userExpr string) string {
	return fmt.Sprintf("SELECT %[1]s.campaign_id FROM %[2]s %[1]s WHERE %[1]s.tenant_id = %[3]s AND %[1]s.user_id = %[4]s",
		alias, View, tenantExpr, userExpr)
}

// MemberCampaignsWithRolesSQL is MemberCampaignsSQL restricted to the
// effective roles in rolesExpr (an SQL text[] expression).
func MemberCampaignsWithRolesSQL(tenantExpr, userExpr, rolesExpr string) string {
	return MemberCampaignsSQL(tenantExpr, userExpr) + " AND " + alias + ".role = ANY(" + rolesExpr + ")"
}

// RoleSQL is a scalar subquery giving the user's effective role in the
// campaign, NULL when they are not on the team.
func RoleSQL(tenantExpr, campaignExpr, userExpr string) string {
	return fmt.Sprintf("(SELECT %[1]s.role FROM %[2]s %[1]s WHERE %[1]s.tenant_id = %[3]s AND %[1]s.campaign_id = %[4]s AND %[1]s.user_id = %[5]s)",
		alias, View, tenantExpr, campaignExpr, userExpr)
}

// FindingVisibleSQL is the condition under which the user sees a pentest
// finding whose campaign column is campaignCol and status column statusCol:
// they are on the campaign team, and a client only once the finding is
// published.
//
// Shape matters for speed: the subqueries never refer to the finding, so
// each runs once per statement (a reference to the finding's status inside
// them made the database re-run the team lookup for every finding), and
// "= ANY(ARRAY(...))" hands the planner the user's campaign ids up front, so
// a pentest list reads the (tenant_id, pentest_campaign_id) index instead of
// every pentest finding of the tenant.
func FindingVisibleSQL(campaignCol, statusCol, tenantExpr, userExpr string) string {
	member := MemberCampaignsSQL(tenantExpr, userExpr)
	return fmt.Sprintf("(%s = ANY(ARRAY(%s AND %s.role <> '%s')) OR (%s NOT IN (%s) AND %s = ANY(ARRAY(%s))))",
		campaignCol, member, alias, ClientRole, statusCol, unpublishedList(), campaignCol, member)
}
