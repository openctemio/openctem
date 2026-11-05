### Fixed: a scan step shows what became of the findings its sensor reported

- A step that reported matches whose assets the platform held for review (an out-of-contract asset type) or did not store used to read "N findings" while the findings list showed none of them. Each step run now also counts the findings held for review (`findings_held`) and the findings not stored (`findings_refused`), and the run map shows "N held for review" and "N not stored" next to the findings and info observation counts.
- Informational matches are stored with severity `info`, not `none` (`none` is a CVSS score of zero). Findings already stored as `none` keep that value.
- Migration 20261105065518 adds `scan_run_steps.findings_held` and `findings_refused` (constant defaults, no table rewrite).
- Sensors older than the nuclei descriptor fix (sensor changelog: nuclei declares `asset:web_origin`) report web origins their descriptor does not declare, so their nuclei findings are held for review in the results quarantine; upgrade the sensor, and approve the held reports.
