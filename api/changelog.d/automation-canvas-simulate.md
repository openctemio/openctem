### Added: the automation builder shows simulate and live, preview, validate and the run trace

- The Automations canvas builds its palette and type pickers from `GET /api/v1/workflows/catalog` only; a step the viewer lacks the permission for is listed with that permission, and a stored step of a removed type shows as "Removed type".
- The builder header shows the mode, the published version and unpublished changes, switches to simulate in one click and goes live through a "Before going live" check (risk class, step-up, a second publisher for high-risk rules). Another publisher approves a pending version; versions can be rolled back.
- Preview puts per-step counts on the canvas and lists what would be sent; Validate lists problems and selects the step each one names.
- A run opens its trace: per-step counts with skipped reasons, deliveries ("Never sent: simulate"), retention, and Continue or Cancel for a run paused at the change cap.
- Run status is spelled `canceled`.
