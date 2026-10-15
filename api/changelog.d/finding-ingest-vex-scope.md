### Security: a VEX statement in a scan report closes only what that scan's command covered

- With `INGEST_VEX=enforce`, a `not_affected` statement in a command-bound
  report now closes a finding only when the report's tool is the command's
  tool, the statement's asset is one the command covers (a connector sync
  covers what its source owns), and the finding was last reported by that
  same tool. Before, any bound report could close the matching finding of any
  asset in the tenant, including findings another scanner reported.
