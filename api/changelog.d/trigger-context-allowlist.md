### Security: a scan trigger may set only allow-listed context keys

- `POST /api/v1/scans/{id}/trigger` used to copy the request's `context` into the run context, removing only `rule_sources`. That context reaches the run's sensor jobs and decides its outcome, so a caller with `scans:execute` could set platform-owned keys (for example `uncovered_targets`, which forces the run partial, or routing and target keys).
- A caller may now set only `reason` (text, at most 500 characters). Any other key, or a `reason` that is not short text, is refused with `400 TRIGGER_CONTEXT_REFUSED`, naming the refused keys. The web console sends no context and is unaffected.
- **Upgrade note:** an API client that sent other keys in the trigger context must stop sending them.
