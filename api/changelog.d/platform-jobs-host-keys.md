### Security: platform-sensor jobs honour the per-host politeness keys

- `get_next_platform_job` no longer hands a platform sensor a job while an acknowledged or running command of the same tenant holds a conflicting host key (the same name or address, or an address and a range scan of one /24 or IPv6 /120 bucket). It takes the same per-bucket advisory locks as a tenant sensor's claim and checks again, so a platform sensor and a tenant sensor, or two platform sensors, never scan overlapping hosts at once (RFC-088).
- Another tenant's commands never hold a job back. Jobs without host keys (passive stages) are unaffected.
