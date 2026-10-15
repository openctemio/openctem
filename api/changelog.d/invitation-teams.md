### Added: invitations can add the invitee to teams

- `POST /api/v1/tenants/{tenant}/invitations` and `POST /api/v1/organization/invitations/preview` accept `group_ids` (up to 20). The invitee joins those teams when they accept, so they no longer join with no data.
- The inviter can add only teams they may add a member to. A team carrying a privileged role needs the owner, with step-up. An external team needs an end of access. A person outside the organization never gets full data access through a team. A team carrying a role above member makes an outside invitee privileged, so the inviter must step up and the invitee needs two-factor. Teams from another organization are refused (404).
- At acceptance the teams are checked again for the inviter. A team they can no longer add to, or one deleted since, voids the invitation, and nothing is granted.
- Migration `002195` adds `tenant_invitations.group_ids` (empty by default; no operator step).
