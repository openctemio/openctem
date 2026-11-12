### Fixed: organizations created for an owner work on an installation without email

- An ownership invitation issued without email is recorded as never sent (`send_count` 0, no
  `last_sent_at`); "Send again" is refused with 409 `EMAIL_UNAVAILABLE` instead of counting a send that did
  not happen. Migration `20261111155507_owner_invitation_not_sent` (constraint and nullability only;
  existing rows unchanged).
- The console says "Not sent: this server cannot send email" on the Owners card, in the create and
  change-invitee dialogs and on the Users tab, hides Send again, Last sent and Sends left, and shows the
  address where the person accepts (`owner_invitation.accept_url`, with a Copy button). An expired
  invitation is renewed with Change invitee and the same address.
- The invited person sees a banner with "Review invitation" wherever they land after signing in (the
  organization shell, or the account space of a person with no organization).
- The new owner's one-time set-password link shown in the console is now the web app's address
  (`setup_url`); the console used to build it from its own site, which has no set-password page.
- New `POST /api/v1/admin/platform-users/{user_id}/setup-link` (organization and reason in the body):
  without email only, a new one-time link for an organization's new owner who has not set a password,
  shown once and never stored in clear; the earlier link stops working. Owner-bootstrap permission,
  fresh step-up, support rate limit, admin and organization audit (never the link), `no-store`.
  Users tab: "New setup link".
