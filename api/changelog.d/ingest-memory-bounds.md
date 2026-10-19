### Security: sensor result uploads are bounded per sensor, for shared sensors, and by the replica's memory

- A sensor may have at most 2 result uploads in flight (429 with Retry-After beyond), so one sensor cannot take every in-flight slot of its organization.
- Shared sensors, which have no organization and so escaped the per-organization cap, together have at most 8 uploads in flight per API replica.
- The byte budget that result uploads reserve before they are read is now a quarter of the container's memory limit (64 MiB to 1 GiB) instead of a fixed 1 GiB, so uploads alone cannot exhaust a 2 GiB API container. Oversized bodies are still refused with 413 before they are read.
