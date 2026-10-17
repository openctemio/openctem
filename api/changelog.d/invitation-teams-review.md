### Security: invitation teams and the public lookup follow the acceptance-time view of the invitee

- When an invitation is accepted, its teams are checked again using the invitee's classification at that moment, no longer the one stored when the invitation was sent. Someone who has become an outsider since then never gets full data access through a team; the invitation is void and nothing is granted.
- The `invitation.accepted` audit event lists the teams granted (`group_ids`).
- The public invitation lookup shows the roles, teams, outside status, end of access and two-factor requirement only while the invitation is pending. An expired or used token reveals none of them.
- An ownership transfer that lapses after 72 hours is closed and audited (`member.ownership_transfer_expired`) as soon as anyone next touches the transfer.
