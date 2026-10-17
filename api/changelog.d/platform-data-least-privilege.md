### Security: the audit log follows data scope; sensor, credential-store and attachment gates tightened

- The audit log (list, stats, single entry, resource history and another user's
  activity) now needs full data access in addition to `audit:read`: a custom
  role with a restricted data scope used to read the names and messages of
  assets and findings outside it. Everyone still reads their own activity.
- The Researcher role template (v2) no longer carries `sensors:read`; existing
  Researcher roles lose it (migration). Quarantined sensor results and a sensor's
  configuration report are owner/admin only, and sensor host names and
  addresses are returned to owners and administrators only.
- Sensor commands `collect`, `config_update` and `cancel` are owner/admin only,
  like scan commands.
- Writing or rotating a credential in the secret store is owner/admin only, and
  the built-in Member role no longer holds `scans:secret_store:write`.
- Attachments: an unknown `context_type` is refused (400) on upload, list and
  link; only `finding`, `retest` and `campaign` are accepted.
- The route authorization coverage gate and the generated authorization
  reference match allowlisted prefixes on a path-segment boundary, so
  `/api/v1/mcp` no longer covers `/api/v1/mcp-access/*`.

### Behaviour change: notification channels send a minimal message unless they opt in

- A channel with "Include details" off now sends only the event type, severity
  and a link, with no finding title, asset name or body. Before, the switch
  was stored but ignored and every message carried full details. New channels
  default to off; the add and edit dialogs explain it (en, vi).
