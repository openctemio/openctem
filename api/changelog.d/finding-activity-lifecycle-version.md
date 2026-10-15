### Added: every status change on a finding's timeline records the lifecycle version

- `finding_activities.lifecycle_version` (also in the entry's `changes` as `lifecycle_version`) is set on every timeline entry that records a status change, whatever wrote it: a person's move, a platform writer, or the transition timeline trigger. Today it is `platform:1`. A tenant lifecycle scheme will record its own version, so an audit can tell which rules applied when a finding moved.
- Older entries stay empty: they were decided before versions were recorded.
- Migration `002460_finding_activity_lifecycle_version` adds a nullable column (a catalog change) and a BEFORE INSERT trigger.
