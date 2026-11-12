### Added: findings filter "Only reported by a retired source"

- `retired_source_only=true` on the findings list (and its counts, groups and export) returns the findings every one of whose sources the organization stopped using: the findings a source retirement kept open or archived that no other source corroborates. `false` is the complement. It uses the retirement classifier's own rule (shared SQL), is tenant-pinned, and runs inside the caller's data scope. The filter picker offers it, and the retired sources section links to it.
