### Security: result uploads share a process-wide decoding budget

- One protocol v2/v3 result request may hold up to 16 MiB on the wire and 64 MiB decoded, and each organization may run 8 at once per replica. Nothing bounded many organizations together, so concurrent uploads could exhaust a replica's memory.
- Every result request now reserves the most it may hold decoded from a budget of 1 GiB per replica before it is read: its body, plus the decompressed size its compression may reach.
- When the budget is spent, the request gets `429 rate-limited` with `Retry-After`, and sensors retry.
