### Changed: automations hear about every way a scan run ends

- The `scan_completed` automation trigger now also fires for runs that time
  out or are canceled, including runs the timeout controller ends (past their
  deadline, or no sensor picked them up). `status_filter` accepts `timeout`
  and `canceled` as well as `completed`, `partial` and `failed`. Without a
  filter it still fires on completed runs only, so existing automations behave
  as before.
