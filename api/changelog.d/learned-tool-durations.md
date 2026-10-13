### Added: the platform learns each tool's time per target

- Every completed scan command is one sample of its tool's time per target
  in its organization (duration × targets worked on at once ÷ targets),
  clamped to the tool's floor and ceiling. The platform keeps a decayed mean
  and p95 per organization and tool (`tool_duration_stats`).
- `toolbudget.Lookup(tenant, tool)` returns the tool's budget with what was
  learned (after 5 samples, the per-target budget follows 1.5 × the learned
  p95, always within the tool's band); the planner and the target pool size
  jobs from it. Failed, canceled and re-queued attempts teach nothing.
