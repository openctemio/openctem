### Security: custom templates reach sensors only in versions people approved

- With the job signer (`SIGNER_SOCKET`), a custom template version is
  approved for sensors like a scope widening: the organization's approval
  count, approvers holding `attack_surface:scope:approve` with step-up, never
  the author of the version. New route
  `POST /api/v1/scanner-templates/{id}/approve`; the Scanner templates page
  shows "Awaiting approval n/m" and an "Approve for sensors" action. With a
  count of 0 a version is approved when it is saved. A new content version
  needs new approvals; deprecating or deleting a template takes it out.
- The job signer records each approved version's digest in its ledger, and
  the signed job lists the digests of the job's custom templates
  (`templates`). The signer refuses any version it did not record
  (`template_not_in_ledger`); the command fails with `SIGNER_REFUSED`. A
  sensor that verifies signed jobs trusts the templates through the job
  (sdk-go); the per-tenant template key is only the fallback for sensors
  without signed jobs.
- Migration `001558` adds `ledger_sha256`, `sensor_approvals` and
  `content_author_id` to `scanner_templates`.
- **Upgrade note:** the current version of every active template counts as
  approved (it ran before). With a job signer, include them in the ledger
  bootstrap (`server -signer-ledger-export` lists them; review before
  `openctem-signer ledger import`). Sensors on an sdk-go older than the one
  that reads `templates` refuse jobs carrying custom templates once signed
  jobs are verified: update the sensors before using custom templates with
  signed jobs.
