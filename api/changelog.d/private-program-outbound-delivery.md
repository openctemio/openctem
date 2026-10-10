### Security: events about private program assets no longer reach organization-wide integrations

- A notification about an asset that only private bug-bounty programs list
  (Slack, Teams, Telegram, email, webhook, Splunk HEC) goes only to the
  integrations a program member attached to one of those programs; with none
  attached nobody receives it. Automations do not start for such events, and
  EASM exposures on such assets are left out of the daily digest.
- Private program names, handles and tags are scrubbed from every message
  bound for a destination not attached to that program, including messages
  about assets the organization also owns.
- New: `GET /api/v1/programs/{id}/delivery`,
  `PUT|DELETE /api/v1/programs/{id}/channels/{integrationId}` (members,
  `integrations:manage`, step-up to attach) and
  `PUT /api/v1/programs/{id}/org-channels` (owners only, reason, step-up),
  all audited.
- Upgrade: migration `program_delivery` adds `bounty_program_channels`,
  `bounty_programs.org_channels_opt_in` (off) and a unique
  `(tenant_id, id)` constraint on `integrations`.
