### Added: the `analyze` command type and the `ai-worker` sensor grant profile

- An AI worker is a sensor on the new `ai-worker` grant profile: it runs analysis jobs (command type `analyze`) and nothing else, at the passive tier, with no target network, no credentials and no push ingest. It can be made Trusted at approval.
- A grant that lists `analyze` lists no other job type, and every scanning profile refuses `analyze`, so one sensor is either an AI worker or a scanner. An `analyze` command carries `required_capabilities: ["analyze.<kind>"]`, so only a worker that advertises the kind claims it; it is signed at claim like every command type.
- Migration 20261113024824 adds `analyze` to the command types, lets a run on an AI worker be queued (or end canceled, refused or failed) before a worker claims it, and adds `ai_runs.result_digest`. It changes no data: both checks only widen the old ones (added NOT VALID, then validated).
- Docs: server/docs/architecture/sensor-pairing.md ("The AI worker profile"), server/docs/rfcs/RFC-131-ai-analysis.md §5
