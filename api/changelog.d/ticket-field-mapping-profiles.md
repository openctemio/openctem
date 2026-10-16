### Added: ticket field and status mapping profiles

- Per tracker destination (integration, project, issue type) and per object
  (finding or remediation task), administrators map OpenCTEM attributes to
  tracker fields and back, and OpenCTEM states to the project's workflow and
  back: value maps, templates, user, date, number and list transforms, sync
  mode and conflict winner per field. Versions have a draft, publish (checked
  against the tracker's live fields and workflow, step-up) and rollback.
- Preview of the exact fields for a finding or task, inbound preview of an
  issue, a simulator for transition paths and inbound intents, presets,
  suggestions, copy between projects, JSON/YAML import and export, and drift
  detection.
- Security: a tracker change can never set severity, scores or a closing
  status; a due date becomes a request and "Won't Do" a risk-acceptance
  request. Rendered text is redacted after templating. Previews respect the
  caller's data scope. Every change is audited.
