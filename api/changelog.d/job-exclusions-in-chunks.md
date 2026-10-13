### Security: scan commands carry the exclusions near their ranges

- Every scan command whose targets include a range (workflow chunks, single-scanner commands, zone batches) now carries the tenant's active address exclusions inside the /24 (IPv6 /120) buckets of its ranges, in the payload key `exclusions`. The job signature covers it.
- Sensors on sdk-go with job exclusions cut their range targets around them again, address by address, and hand them to tools that can skip hosts. Older sensors ignore the key; the pieces the platform dispatches already leave excluded addresses out (RFC-088).
- A failed exclusion lookup creates no command (fail closed); more than 4 096 exclusion prefixes for one job is `RANGE_TOO_FRAGMENTED`.
