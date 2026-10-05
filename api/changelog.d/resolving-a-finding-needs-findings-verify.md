### Behaviour change: resolving a finding needs findings:verify

- **Members can no longer close findings as resolved** (research 18 F1,
  owner decision O12). Moving a finding to `resolved` now needs
  `findings:verify` from every status, `fix_applied` included, on every path:
  `PATCH /findings/{id}/status`, `POST /findings/bulk/status`,
  `POST /findings/remediation-groups/{key}/resolve` and remediation campaign
  resolve. Before, a Member (`findings:fix_apply` + `findings:bulk_update`)
  could mark findings `fix_applied` and then bulk-close them with no
  checklist and no proof of fix. Without the permission these calls now
  answer **403** and change nothing. Members keep `fix_applied`; a retest, a
  verified scan or a security reviewer closes the finding. The web hides
  "Resolved" from people without the permission. Give `findings:verify` to a
  custom role if a team should keep closing findings by hand.
- **Every human resolve records how and by whom.** The single, bulk, group
  and campaign paths stamp `resolution_method` (`security_reviewed` when the
  finding's verification checklist is complete, `admin_direct` otherwise) and
  `resolved_by`, and the bulk path now writes a status-change activity per
  finding. Any move away from `resolved` clears `resolution_method`.
- The unused, unguarded `VulnerabilityService.BulkUpdateFindingStatus` was
  removed.
