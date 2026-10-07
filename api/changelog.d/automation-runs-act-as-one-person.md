### Security: automation runs act as one person, checked before every step

- A manual run (`POST /api/v1/workflows/{id}/runs`) acts as the caller. It names
  its subject with `finding_id` or `asset_id`; `trigger_data` and trigger types
  other than `manual` are refused. The caller needs the permission of every step
  and the subject in their data scope. Before, any holder of
  `findings:workflows:write` could make an administrator's automation change any
  finding by naming it in `trigger_data`.
- An event run acts as the automation's owner (`created_by`). Creating, switching
  on, or changing what an automation does makes the editor its owner. Before each
  action and notification step the owner is checked live (active member,
  the step's permission, the subject in their data scope); a refused step fails
  with `AUTOMATION_RUN_NOT_AUTHORIZED` and changes nothing.
- Adding or removing an edge, deleting or editing a node, and switching an
  automation on need the permission of every step, like adding one. Notification
  steps need `integrations:read`; outbound HTTP needs `integrations:manage`.
- The `http_request` action is retired (outbound calls go through a notification
  integration): new nodes are refused, a stored one no longer runs (its step
  fails), its header values are no longer returned by the API, and response
  bodies and headers are no longer stored with the run. Building one needed
  `integrations:manage`.
- **Upgrade note:** an active automation with no owner (`created_by` empty) runs
  no step until someone with the needed permissions saves or switches it on again.
