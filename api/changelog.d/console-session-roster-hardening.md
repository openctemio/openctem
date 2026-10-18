### Security: platform console sessions idle out and roster changes are announced

- An open console tab no longer stays signed in for the full 8 hours: the
  console's own periodic refreshes carry `X-Admin-Background: 1` and do not
  count as activity, so a tab nobody uses signs out after 15 minutes.
- A password reset or change, or a two-step reset, of a platform
  administrator's account now also ends that administrator's console
  sessions (audited as `console.sessions_ended_by_account`).
- Adding, changing or removing an administrator, resetting one's console
  sign-in, changing the administrators' identity provider or the
  security-key policy is emailed to every other active administrator and
  logged with `alert=admin_roster_change`.
- Publishing or ending an announcement, changing an organization's limits or
  idle policy, turning a threat-intelligence feed on or off, and blocking or
  unblocking an AI application now ask for a step-up.
- The console sends `Strict-Transport-Security`, and its API proxy no longer
  shows network error details when the API cannot be reached.
