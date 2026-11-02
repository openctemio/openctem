### Changed: shorter notification settings, a help line on the console's "Everyone" floor

- My account > Notifications: notification kinds have short sentence-case names, and a one-line hint only where the name alone does not say it (approvals, AI application requests, the digest, SLA breaches, system alerts). Redundant lines (on/off echo, repeated card text) are gone.
- Console > Two-factor: the "Everyone" floor stays available and says it is the operator's call on a self-managed install, and that members need an authenticator app until organization passkeys exist.

### Fixed: settings pages no longer show a failed load as empty

- My account > Activity, My account > Connected applications, Settings > AI assistants (organization connections) and Settings > Domains show "Failed to load" with Retry when the request fails, instead of "nothing here".
