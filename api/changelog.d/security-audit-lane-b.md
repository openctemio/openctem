### Security: stored secrets no longer follow a changed destination

- Notification channels: moving an email channel to another SMTP host or port (or weakening its TLS mode), or a Splunk channel to another collector host, now requires entering the credentials again; the old ones are never sent to the new destination, including by the test delivery after an update.
- Console identity providers: changing the issuer (or the Entra directory) requires the client secret to be entered again. Tenant evidence storage: changing the provider, endpoint, bucket or region requires new access keys.
- `integrations:manage` and `integrations:scm:write` are privileged permissions: giving them to a custom role needs a recent sign-in, binding a role that carries them to a team is for the owner, and an outside member holding them counts as above the member role. Built-in owner and admin roles are unchanged.
- Lowering a finding false-positive or risk-acceptance approval level, or relaxing the approval policy (including turning two-person approval off), now requires the organization owner; administrators can still raise levels. Administrators and approvers are notified as before.
- `PATCH /organization/members/{id}/access` needs a recent sign-in when it widens access (later end date, no end date, or re-enabling a member).
- When the revoked-session lookup is unavailable, write requests are refused with 503 and read requests continue for two minutes, then are refused until the lookup recovers (previously every request continued until the token expired).

### Removed: unused web server actions

- Removed the unused `refreshTokenAction`, `logoutAction`, `handleOAuthCallback`, `getCurrentUser` and `isAuthenticated` server actions and the unused `useAuth` hook; sign-in, refresh and sign-out go through the existing route handlers and local-auth actions.
