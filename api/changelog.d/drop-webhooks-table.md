### Removed: the retired outbound webhooks table

- Migration 001069 drops `webhooks`. The outbound webhooks feature never
  delivered anything; its API and permissions went in 001032. The table only
  held configuration rows of that removed feature (3 on production, created on
  one day and never used); they are dropped with it.
- Encryption-key rotation (`cmd/rekey`) no longer rewraps
  `webhooks.secret_encrypted`, and the sensor-rename upgrade check no longer
  counts event names in it.
- Upgrade in one step: no configuration change. The down migration recreates
  the empty table; the dropped rows are not restored.
