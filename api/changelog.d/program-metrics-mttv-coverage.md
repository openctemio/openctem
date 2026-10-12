### Added: more CTEM program metrics on Program Health

- `GET /api/v1/dashboard/program-metrics` (and Insights > Program Health)
  adds four metrics computed from data the platform already stores, each
  tenant-scoped, with `null` (shown as "—") when there is no sample:
  - `mttv`: time from detection to the first conclusive validation of P0/P1
    findings, with the count still waiting for validation;
  - `time_to_owner_internet_facing`: time from discovery to the first owner of
    new internet-facing assets, with the count still without an owner;
  - `cycle_completion`: CTEM cycles closed by their end date, and the mean
    charter success-criteria completion at close;
  - `control_coverage`: critical and crown-jewel assets whose EDR, MFA or
    logging attribute is false or not recorded (a snapshot of the inventory).
- Program Health metric texts are translated (en, vi). No migration.
