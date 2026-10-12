### Security: a scan job's targets are re-checked against the current scope when a sensor claims it

- A scan job can wait in the queue while its scope changes (an exclusion added, a scope entry removed or its tier lowered, an asset's ownership rejected, a scan zone deleted or shrunk, the actor's act scope revoked). The dispatch gate now runs again on every hand-out path (protocol v2 listing poll, claim-N and claim by id; protocol v3 `ClaimCommands` and claim), with the inputs the dispatch recorded (new column `commands.dispatch_gate`, migration 001352, platform-written only).
- Targets refused since dispatch are taken out of the job, in what the sensor gets and in the stored payload. A job left with no target is not handed out: it fails with `SCOPE_CHANGED` (also on its step, failure class `scope`, not retried), recorded once; a claim by id answers `command-claimed`.
- If the check cannot run, the job is withheld and stays pending (fail closed); the command expiry ends a job that can never be checked.
- **Upgrade note:** scan jobs queued before the upgrade have no record and are re-checked with the baseline rules (exclusions, rejected names, private-address and zone rules).
