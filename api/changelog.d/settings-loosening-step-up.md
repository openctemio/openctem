### Security: loosening the pentest tracker limit or turning on auto-resolve needs a recent sign-in

- `PATCH /api/v1/tenants/{tenant}/settings/pentest`: raising `ticket_max_tlp` (more sensitive campaign findings may reach Jira or GitHub Issues) or turning off `require_authorization_before_start` now needs step-up re-authentication (403 `STEP_UP_REQUIRED`), is audited at high severity and sends every owner and administrator an in-app notice. Tightening and other edits are unchanged.
- `PUT /api/v1/organization/settings/retest`: turning `auto_resolve` on (auto-retest closes findings without a person) gets the same step-up, high audit and notice.
- The web console's pentest page already uses the shared client, so it asks for the sign-in and retries.
