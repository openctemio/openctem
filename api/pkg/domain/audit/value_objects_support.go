package audit

// Support access (docs/rfcs/RFC-063-support-access.md): an owner's grant to a
// named platform administrator, and every support session and read under it.
// The actor of the session events is "support:<administrator email>".
const (
	// ResourceTypeSupportGrant is an organization's support access grant.
	ResourceTypeSupportGrant ResourceType = "support_grant"

	ActionSupportGrantCreated   Action = "support.grant_created"
	ActionSupportGrantRevoked   Action = "support.grant_revoked"
	ActionSupportSessionStarted Action = "support.session_started"
	ActionSupportSessionEnded   Action = "support.session_ended"
	// ActionSupportAccessed: one read by a support session (route, resource).
	ActionSupportAccessed Action = "support.accessed"
)

var _ = registerActions("support", map[Action]Severity{
	ActionSupportGrantCreated:   SeverityHigh,
	ActionSupportGrantRevoked:   SeverityMedium,
	ActionSupportSessionStarted: SeverityHigh,
	ActionSupportSessionEnded:   SeverityMedium,
	ActionSupportAccessed:       SeverityMedium,
})
