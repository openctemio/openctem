### Security: automations only request false positives and risk acceptances

- New actions `request_false_positive` and `request_risk_acceptance` create a request on behalf of the automation's owner. A person always decides it. The approval policy never lets one person decide a request an automation made, even when the organization's approval level is `off`.
- `update_status` may move a finding only to `confirmed` or `in_progress`. Other targets are refused on save (400 `AUTOMATION_STATUS_NOT_ALLOWED`) and at run time. Migration 003353 (`automation_guardrails`) switches off, and back to simulate, every automation whose draft or published version set another status (`disabled_reason = status_not_allowed`). No automation is deleted.

### Added: change cap per automation run

- A live run makes at most `max_changes_per_run` changes: 250 by default, at most 1,000, set on the automation and pinned by each version. A cap above 250 makes the automation high risk. At the cap the run pauses (`status: paused`, `pause_reason: blast_radius`) until a publisher lets it continue (`POST /api/v1/workflow-runs/{id}/resume`).
