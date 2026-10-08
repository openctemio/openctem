### Security: validate, retest and connector scan jobs are re-checked against the current scope at claim

- The claim-time scope re-check now covers validate commands (finding re-checks, proof-of-fix, attack-simulation safe-checks), tool retests and `connector_scan` jobs (scan runs and coverage batches), not only scans. Each records the gate it passed at dispatch (`commands.dispatch_gate`, no new migration) and is re-checked with it when a sensor claims it.
- A job whose target is now refused fails with `SCOPE_CHANGED`, and what waits on it is settled as on a sensor failure: its validation run finishes as failed, its retest is settled, its scan step fails.
- Jobs of these types queued before the upgrade have no record and are handed out as before; they expire with the command TTL.
