### Fixed: a malformed scope target pattern is answered 400, not 500

- `POST /api/v1/scope/targets` (and `/preview`) with a pattern that does not fit its type, or an unknown target or exclusion type, now answers 400 with what is wrong instead of 500.
- A bare 12-digit AWS account id as a `cloud_account` pattern is refused with the accepted form, `AWS:<account id>`.
- Pattern refusals no longer echo the submitted pattern back, except the AWS hint.
