### Security: unrelated secrets no longer share a rotation group or merge into one finding

- A secret's rotation group (`rotate:secret:<fingerprint>`) is now derived only from the keyed hash of its raw value (the producer's `secretHMAC/v1`, or the server's own hash of a raw value in the report). It used to be derived from the mask, so every short secret of a tenant (`REDACTED`) and every AWS key (`AKIA********`) landed in one rotation suggestion, and one rotation proof could close unrelated live credentials. A secret reported only as a mask now gets no rotation group.
- Marker words such as `REDACTED` or `[hidden]` count as zero visible characters when deciding whether a mask tells two secrets apart, so two different short passwords of one rule in one file stay two findings.
- **Upgrade note:** findings stored before this change keep their mask-derived fingerprint until the secret-fingerprint reset command (separate change) is run.
