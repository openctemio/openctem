### Security: an IP allowlist change reaches every API replica at once

- Each API replica cached an organization's IP allowlist for 30 seconds and only the replica that saved the change dropped it, so other replicas kept admitting a removed address for up to 30 seconds. The change is now published on Redis and every replica drops its cached entry at once.
- The 30 second cache bound remains for a lost message or a deployment without Redis. The message carries only a tenant id and can only drop a cache entry.
