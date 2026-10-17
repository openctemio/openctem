### Security: a CI job's OIDC token re-exchanged gets the same run only, and refusals say why

- The same OIDC token presented again while valid (same bytes, same
  organization) gets a new upload token for the run it already opened or
  joined, and nothing wider: at most five exchanges per token, each audited
  with its count. Before, the second exchange was refused, so a job that lost
  the first answer, or ran `openctem-ci` more than once, could not report.
  Any other token under a used token id, or one presented to another
  organization, is still refused and audited at high severity (migration
  `002137`).
- A plain run's id is chosen at the first exchange: a re-exchange after a
  failed creation makes that run, never a second one.
- Refusals after the organization's trust configuration admitted the token
  now tell the pipeline the reason (`CI_TOKEN_REPLAY_LIMIT` with the first
  exchange time and run, `CI_TOKEN_REPLAY_RUN_CLOSED`, `CI_TOKEN_PIPELINE_RATE`
  and others). Refusals before admission stay one generic
  `CI_TOKEN_NOT_TRUSTED` that lists what to check, so a token from a stranger
  on a shared issuer learns nothing about the configuration.
