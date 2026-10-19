package adminconsole

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/brand"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

// Roster changes: who may administer the platform and how administrators
// sign in. A single administrator's session can make such a change on its
// own (create a super admin, loosen the sign-in policy), so every other
// active administrator is told at once. A change nobody expected is then
// noticed in minutes instead of at the next audit review.

// AlertRosterChange is the stable value of the "alert" field on the WARN log
// line written for every roster change, for log-based alerting without email.
const AlertRosterChange = "admin_roster_change"

// Roster change kinds (the RosterChange.Kind values).
const (
	RosterAdminAdded       = "admin_added"
	RosterAdminUpdated     = "admin_updated"
	RosterAdminRemoved     = "admin_removed"
	RosterCredentialsReset = "admin_credentials_reset"
	RosterSignInPolicy     = "console_sign_in_policy"
	RosterIdentityProvider = "platform_identity_provider"
	RosterIdPUnbound       = "admin_idp_unbound"
)

// RosterChange describes one change for the notice.
type RosterChange struct {
	Kind string
	// Summary is one English sentence for the email ("added x@y as Super
	// admin"). It never carries a secret.
	Summary    string
	ActorEmail string
	IP         string
	At         time.Time
	// Recipients are the other active administrators' emails.
	Recipients []string
	// Via says where the change was made, completing "<actor> <summary> ...";
	// empty means the admin console. The bootstrap-admin command sets it.
	Via string
}

// RosterChangeEmail renders the notice's subject and HTML body. Every value
// from the change is put on one line and HTML-escaped.
func RosterChangeEmail(appName string, c RosterChange) (subject, body string) {
	name := appName
	if name == "" {
		name = brand.DefaultName
	}
	oneLine := strings.NewReplacer("\r", "", "\n", "")
	who := oneLine.Replace(c.ActorEmail)
	via := oneLine.Replace(c.Via)
	if via == "" {
		via = "in the " + name + " admin console"
	}
	subject = fmt.Sprintf("[%s] Administrator change by %s", name, who)
	body = fmt.Sprintf(`<p><strong>%s</strong> %s %s.</p>
<ul><li>Time: %s</li><li>IP address: %s</li></ul>
<p>Every change to the administrators, their sign-in or the console sign-in policy is sent to all administrators. If you did not expect this one, treat it as an incident: review the admin activity log and end the administrator's sessions.</p>`,
		html.EscapeString(who), html.EscapeString(oneLine.Replace(c.Summary)), html.EscapeString(via),
		html.EscapeString(c.At.UTC().Format(time.RFC1123)), html.EscapeString(oneLine.Replace(c.IP)))
	return subject, body
}

// RosterChangeNotifier delivers the notice. Implementations must not block the
// change (send asynchronously).
type RosterChangeNotifier interface {
	NotifyRosterChange(ctx context.Context, c RosterChange) error
}

// SetRosterChangeNotifier wires the notifier (email in production).
func (s *Service) SetRosterChangeNotifier(n RosterChangeNotifier) { s.rosterNotifier = n }

// NotifyRosterChange writes the WARN alert line and tells every other active
// administrator. The change itself is audited by its own action; this is the
// out-of-band notice. Handlers outside this package (administrator update and
// delete) call it after a successful change.
func (s *Service) NotifyRosterChange(ctx context.Context, actor *admin.AdminUser, kind, summary string, client ClientInfo) {
	recipients := []string{}
	if others, err := s.admins.ListActive(ctx); err != nil {
		s.log.Warn("list administrators for roster notice", "error", err)
	} else {
		for _, o := range others {
			if actor == nil || o.ID() != actor.ID() {
				recipients = append(recipients, o.Email())
			}
		}
	}
	actorEmail := ""
	if actor != nil {
		actorEmail = actor.Email()
	}
	s.log.Warn("platform administrator roster or sign-in policy changed",
		"alert", AlertRosterChange,
		"kind", kind,
		"actor", logSafe(actorEmail),
		"ip", logSafe(client.IP),
		"notified", len(recipients),
	)
	if s.rosterNotifier == nil || len(recipients) == 0 {
		return
	}
	if err := s.rosterNotifier.NotifyRosterChange(ctx, RosterChange{
		Kind:       kind,
		Summary:    summary,
		ActorEmail: actorEmail,
		IP:         client.IP,
		At:         s.now(),
		Recipients: recipients,
	}); err != nil {
		s.log.Warn("notify administrators of a roster change", "alert", AlertRosterChange, "error", err)
	}
}

// roleLabel is the English role name used in notices.
func roleLabel(r admin.AdminRole) string {
	switch r {
	case admin.AdminRoleSuperAdmin:
		return "Super admin"
	case admin.AdminRoleOpsAdmin:
		return "Operations admin"
	case admin.AdminRoleReadonly:
		return "Read-only admin"
	}
	return string(r)
}

// RoleLabel exposes roleLabel to handlers composing a notice.
func RoleLabel(r admin.AdminRole) string { return roleLabel(r) }
