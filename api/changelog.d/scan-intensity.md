### Added: scan intensity (passive, active, intrusive)

- Every scan has an `intensity`, the ceiling of what its runs may send toward
  the targets: `passive` (no packets from the sensors to the targets),
  `active` (non-intrusive probing) or `intrusive` (RFC-071). It is on scan
  create, update, quick scan, import/export and the scan and run responses.
- A scanner or workflow step above the intensity is refused when the scan is
  saved (`INTENSITY_EXCEEDED`); at run time such a step is skipped with its
  reason and never dispatched; the claim refuses a job whose tier, or the tier
  the sensor's tool contract gives it, is above.
- Existing scans get the tier they already probe at (migration
  `scan_intensity`); nothing changes behaviour.

### Security: passive steps take only names in the organization's scope

- A passive (T0) step or chained stage may still resolve a name nobody
  confirmed yet, but no longer any name outside the organization's scope
  (refused `no_entry`).
- Passive stages declare where their traffic goes (`egress-proxy`,
  `resolver`, `vendor`, `none`); a passive step whose tool reaches its
  targets is refused. dnsx with custom resolvers counts as active. The tool
  contract accepts `network: resolver`.
