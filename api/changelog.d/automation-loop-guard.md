### Security: automations cannot trigger each other in a loop

- An event caused by an automation step (a status change it made, the end of a
  scan it started) never starts the automation that caused it. It starts other
  automations only when they allow it with
  `trigger_config.allow_automation_triggers: true` (off by default), never past a
  chain depth of 3, and at most once per finding in 10 minutes. AI-triage events
  have the same cooldown.
- **Behaviour change:** an automation that ran on status changes made by another
  automation no longer does, unless it sets `allow_automation_triggers`.

### Fixed: stuck, hung and failing automation runs end

- Automation runs that a restart left pending or running are failed with their
  open steps. The `automation-run-reaper` controller does this on start and every
  15 minutes, for runs over an hour old.
- The 30-second per-step limit is applied. A hung step fails, and the run goes on
  to its next step.
- An automation whose latest 20 runs all failed is switched off (audited, reason
  `consecutive_failures`).
- When a run finishes, it no longer switches back on an automation that was
  switched off while the run was executing.
