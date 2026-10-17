### Security: outside members' two-factor rule counts team roles; invitation limits are atomic

- An outside member whose role above member comes from a team (a team role binding with member, team, role, API key or settings administration, or full data access) now needs two-factor at every sign-in to the organization, like one with a direct role. Joining such a team already needed the owner with a recent sign-in.
- Two resends of the same invitation at the same moment send one mail: the second is refused (429 `INVITATION_RESEND_TOO_SOON`).
- The per-inviter hourly cap, the daily plan limit and the seat check run under a per-organization lock with the insert, so concurrent invitations cannot pass a limit together.
- `security.invitees = allow_list` also admits the organization's verified domains (documented).
