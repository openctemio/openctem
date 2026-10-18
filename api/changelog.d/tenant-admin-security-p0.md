### Security: privileged role grants, integration writes and loosened sign-in security are guarded

- Giving a user a privileged custom role they do not hold (direct grant, role replacement or bulk assign) now needs the acting administrator's recent re-authentication, and so does an edit that makes a directly-held custom role privileged. System paths (SCIM, SSO, invitation acceptance) are unchanged.
- Organization-wide scan configuration is owner and administrator only: a scan profile's quality gate and default flag, the tool settings (single and bulk) and deleting a secret-store entry. Members whose role carries the write permission now get 403.
- Connecting, changing, disabling or deleting an integration, creating a notification channel, changing a channel's settings and saving the SCIM group-to-role mapping need step-up re-authentication.
- Loosening sign-in security (administrators' two-factor requirement off, personal-account policy relaxed, approval of new single sign-on members off, a sign-in exception added) is graded High in the audit log, and every High or Critical security-settings change now sends an in-app notice to all owners and administrators naming who changed what.

### Fixed: leave flow reachable by members, honest settings copy, ownership-transfer read

- "Leave organization" moves to My account, Organization membership, so members and viewers can reach it; the only owner sees it disabled with the reason.
- The Authentication and General settings descriptions no longer promise a session length or localization setting that does not exist.
- `GET /api/v1/organization/ownership-transfer` answers 200 with `null` when no transfer is pending instead of a 404.
- The scan-profile "Set as default" action is hidden from members, who cannot use it.
