### Fixed: a refused "Run now" no longer creates a blocked run

- `POST /scans/{id}/trigger` that is refused (for example `NO_RUNNABLE_STEPS`, 400, "nothing was started") now creates no run at all: the refusal is the answer, and it is written to the audit log with its code. Before, the same request also added a blocked run to the scan.
- Refusals of automatic triggers (schedule, retry, automation) are still recorded as blocked runs, so a scheduled run that could not start still shows on the scan.
- Docs: server/docs/architecture/tool-availability.md, server/docs/architecture/scan-stages.md, server/docs/rfcs/RFC-046-scans-redesign.md
