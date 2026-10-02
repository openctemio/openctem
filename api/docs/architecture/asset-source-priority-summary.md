# Asset Source Priority — Executive Summary (for customer review)

> **Audience**: Business / security leads · **Time to read**: 5 minutes
>
> **Full technical RFC**: [asset-source-priority.md](./asset-source-priority.md)
>
> **Implementation plan**: [asset-source-priority-impl-plan.md](./asset-source-priority-impl-plan.md)

## The problem, in your words

> "We have multiple data sources feeding OpenCTEM. Some we trust more than others. Today, whichever runs last silently overwrites what the trusted source just reported. We want to name a trusted source, and have OpenCTEM respect it."

## The fix, in one diagram

```
TODAY — last writer wins:

   Nessus (trusted) ──┐
   AWS cloud sync ────┼──▶  [same asset]  ──▶  fields look like the most
   Manual entry ──────┘                         recent run, regardless of trust


WITH THIS CHANGE — trusted source wins:

   Nessus (trusted) ──▶ writes: CVE, severity, OS
   AWS cloud sync ────▶ tries to write CVE → BLOCKED (Nessus ranks higher)
                        writes: cloud tags, account ID ✓
   Manual entry ──────▶ tries to write severity → BLOCKED
                        writes: business owner ✓
```

Each field keeps the value from the **highest-trust source that has written it**. A lower-trust source can still add *new* fields it knows about — it just cannot overwrite fields a trusted source already owns.

## What you will see in the UI

Two places surface the setting:

1. **When you create an agent, integration, or CSV import** — a dropdown:

   ```
   ┌──────────────────────────────┐
   │ Trust level                   │
   │ ○ Primary    ← always wins    │
   │ ● High                         │
   │ ○ Medium    (default)          │
   │ ○ Low       ← always loses     │
   └──────────────────────────────┘
   ```

   Default is `Medium` — neutral. Pick higher or lower to express which sources you trust.

2. **Settings → Asset Sources** (optional, for fine-tuning) — drag-and-drop list showing every source with its current bucket. Power users can adjust without creating new sources.

Optionally, each asset detail panel will show a small tag next to each field:
`OS: Linux — from Nessus · 2h ago`. Lets your team trace where any value came from.

## What is safe about this change

- **Opt-in.** Tenants that do nothing get today's exact behavior. No silent switch.
- **No data rewrite.** Your existing assets are not touched by the migration.
- **Reversible in minutes.** Clear the list to return to today's behavior. No lock-in.
- **Fail-open.** If the system ever gets confused (DB error, deleted source), it allows the write instead of blocking it. We would rather be wrong about ordering than lose your data.
- **Field-level merge already exists.** We are *not* changing how fields merge — we are adding a trust check *before* the merge.

## What we need from you

Before we write code, we need your call on nine questions. The technical RFC has the full context; this is the ballot.

| # | Question | Our recommended default | Your call |
|---|---|---|---|
| 1 | Should `tags` union across sources, or respect trust like other fields? | **Respect trust** (consistent with everything else) | ☐ union  ☐ trust |
| 2 | If a listed source (`High`) competes with an unlisted source, should the listed one always win? | **Yes, always win** | ☐ yes  ☐ no |
| 3 | Two unlisted sources fight over a field — first-write-wins or last-write-wins? | **Last-write-wins** (matches today's behavior) | ☐ first  ☐ last |
| 4 | Per-field lineage — store in `asset_sources` JSON column, or a separate audit table for long-term history? | **JSON column** (simpler, one place to look) | ☐ JSON  ☐ separate table |
| 5 | When a data source is deleted, keep its attributions (with a "deleted" flag) or strip them? | **Keep with flag** (safer for audit) | ☐ keep  ☐ strip |
| 6 | Ship a sensible default priority out of the box? | **Yes**: `Manual > Scanner > Integration > Collector` | ☐ yes  ☐ no, start empty |
| 7 | Trust vocabulary — 4 buckets (`Primary/High/Medium/Low`), or numeric 1–10? | **4 buckets** — simpler, enough for v1 | ☐ buckets  ☐ numeric |
| 8 | Inside the same bucket, how to tie-break? | **Last-write-wins** (today's feel) | ☐ last-write  ☐ by creation date |
| 9 | Default trust level at migration for existing sources? | **Manual → Primary, everything else → Medium** | ☐ proposed  ☐ different |

## Timeline

| Stage | Duration | What happens |
|---|---|---|
| Customer review (you) | 1 week | Answer the 9 questions · optional 30-min call to clarify |
| RFC finalization | 2 days | We update the RFC with your decisions, mark it `Accepted` |
| Build Phase 1 | ~2.5 weeks | Six small releasable increments (see impl plan) |
| Staging validation | 3 days | Run with your real sources, confirm behavior matches expectation |
| Production release | 1 day | Ship behind opt-in — tenants that don't flip a switch see no change |

**Earliest availability**: ~5 weeks from sign-off. Each stage is independent — a delay in review doesn't waste built code because nothing is built until the RFC is accepted.

## What this change does NOT do (Phase 2 candidates)

To keep scope tight and ship v1 on time, the following are **explicitly out**:

- "Use Nessus for CVEs but osquery for OS" — per-field rules. Needs a separate design. Revisit once Phase 1 is live and we see real conflicts.
- Reprocessing historic assets with the new priority — your existing data has no source lineage, so we cannot retroactively apply rules. Phase 1 starts fresh from the first post-release write.
- "Smart" tie-breakers — highest-severity-wins, most-recent-wins. Phase 2 if customers ask.
- Per-asset overrides — "this one asset's OS is manually set, ignore all scanners forever." Phase 2.

None of these are technical blockers — they are scope choices. If any is critical for you, tell us now and we can re-prioritize Phase 1.

## One-sentence ask

**Please review the 9 questions, check your preference, and send it back — or book a 30-min call and we will walk through them together.**
