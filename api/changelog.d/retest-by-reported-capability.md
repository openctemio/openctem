### Changed: retests follow what the sensors report they can re-check

- Auto-retest picks findings of every tool that an online sensor of the organization reports it can re-check. That is either the tool's own retest handler (capability `retest:<tool>`) or the template re-verify rung. Before, only nuclei findings were ever auto-retested. With no such sensor online, nothing is queued, and the next tick tries again.
- `GET /api/v1/findings/{id}/retests` returns `can_retest`, which says whether a retest would be accepted now. It runs the same eligibility checks, target gates and sensor availability as a request, and records nothing. The console offers "Retest now" from it on a finding of any tool, instead of on nuclei findings only.
- The only tool name left in the retest and validation paths is the engine of the template re-verify rung (`validation.ReverifyTool`) (RFC-094 §4.6).
