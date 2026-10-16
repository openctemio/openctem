### Security: signed jobs mark shared-sensor jobs, and the signer applies shared-job rules

- A job queued for shared sensors is signed with `sensor_scope: "instance"`.
  The signer signs such a job only for `scan`, `validate` or `retest`, with
  no custom templates, and with public targets only (ctis `addrscope`, the
  list sensors use; names with internal suffixes refused), whatever the API
  asks. Any other `sensor_scope` is refused.
- A shared sensor must require the field, its own `sensor_id`, and bind the
  job's results to the statement's `tenant_id`; an organization's sensor
  refuses a statement that carries it (job-signing.md).
- The signer and the API's shared-sensor check refuse hosts whose last label
  is all decimal, octal or hex digits (`2130706433`, `0x7f.1`, `127.1`):
  tools that accept the legacy inet_aton forms read them as addresses.
- Upgrade note: no action. Organization jobs are signed exactly as before;
  shared sensors stay unavailable.
