### Added: teams in the invite dialog, and an acceptance page that says what the invitee gets

- The invite dialog lists the organization's active teams. The inviter can add the invitee to some of them, so the person does not join with no data. A team the inviter cannot add people to is explained before sending.
- The public invitation lookup (`POST /api/v1/invitations/lookup`) returns:
  - the roles with their risk summary;
  - the teams;
  - the end of access;
  - whether the person is outside the organization;
  - whether two-factor authentication will be required, and why.
- The acceptance page shows all of this before the person accepts.
- Declining is offered to everyone, signed in or not. It asks for confirmation and then says that the invitation was declined, instead of redirecting.
- The acceptance page's text is translated (English and Vietnamese).
