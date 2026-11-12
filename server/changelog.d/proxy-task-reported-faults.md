### Fixed: a proxy that jobs report as down is quarantined

- A proxy pool endpoint stayed "healthy" while the jobs through it reported
  hosts the pool could not carry (`proxy_unavailable` coverage gaps): its
  health came only from the sensor's separate egress report. The platform now
  records the pool and endpoints it hands each pooled scan, retest or
  validate job (new table `proxy_command_egress`, migration
  `20261030060530_proxy_command_egress`) and charges each ended job's proxy
  verdict to exactly those endpoints. 5 faulted jobs in 30 minutes, or more
  than half of at least 5 jobs, quarantine the endpoint; the quarantine is
  audited (`proxy_pool.endpoint_quarantined`, `source: task_reports`) and
  counted (`openctem_proxy_endpoint_quarantines_total`,
  `openctem_proxy_task_verdicts_total`). Target-side failures never count, a
  sensor cannot name an endpoint it was not handed, and another
  organization's jobs never touch a pool.
