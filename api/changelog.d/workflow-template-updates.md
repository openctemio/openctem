### Added: copies of system scan workflows are offered the template's later changes

- A tenant's copy of a system scan workflow keeps its lineage: the template it was made from and the template's steps as the copy took them. Copies made earlier get it from the audit event of the copy or from the template's name.
- When the template changes (Network gained Host discovery), the workflow builder shows "Update available: add Host discovery" with a preview of each change: steps the template added, and steps it rewired that the copy still has as they were.
- Applying it (scan workflows write) publishes a new version of the copy and is audited; dismissing keeps the copy and stops the offer. A tenant workflow is never changed on its own.
- API: `GET /api/v1/scan-workflows/{id}/template-update`, `POST .../template-update/apply`, `POST .../template-update/reject`.
- Migration `workflow_template_lineage`: two nullable columns on `scan_workflows` and a backfill of existing copies.
