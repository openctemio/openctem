### Security: bulk status change never overwrites a finding that changed after it was read

- `POST /api/v1/findings/bulk/status` now writes each finding only while it is still in the status the request read it in. Before, a finding turned into an approved false positive (or moved by a retest or another person) between the read and the write could be moved back, and the timeline recorded the stale old status.
- Such rows are not changed and are reported: the response now carries `skipped` and `rows` (finding id, outcome `skipped`, `failed` or `conflict`, reason); a conflict also counts in `failed`, so existing clients keep showing "N not changed".
