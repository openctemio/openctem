# Asset Source Priority — Review Meeting Agenda

> **Duration**: 30 minutes · **Format**: Video call, 1 facilitator, 1 scribe
>
> **Objective**: Lock the 9 open questions so the RFC can move from `Draft` to `Accepted` and Phase 1a can start.
>
> **Related**: [RFC-003](./asset-source-priority.md) · [Executive summary](./asset-source-priority-summary.md) · [Implementation plan](./asset-source-priority-impl-plan.md)

## Attendees

| Role | Why they are here |
|---|---|
| Customer security lead | Owns the trust-level semantics. Answers Q1–Q6. |
| Customer ops / admin | Owns the rollout surface. Answers Q7–Q9. |
| Platform tech lead | Keeps the answers technically feasible. |
| UI lead | Flags any UX consequence of the answers. |
| Scribe | Captures the decision log in-meeting. |

If the customer side can only send one person, the security lead takes priority.

## Pre-read (required — send 48h before)

Every attendee confirms by email they have read:

1. The **executive summary** (5 min). Has the 9-question ballot.
2. The "What this change does NOT do" section of the summary. Prevents scope drift in the meeting.
3. (Optional, technical reviewers only) the RFC body.

If someone arrives without the pre-read, reschedule — a call where people read live is a waste of everyone's time.

## Running order

### 00:00–00:02 — Frame

Facilitator reads aloud:

> "In 28 minutes we need 9 decisions. The RFC has recommendations for each; we're here to confirm them, not re-litigate. If a question needs more than 2 minutes of debate, we park it and decide async."

Park-queue goes on a shared whiteboard. Parked items do not block Phase 1a if they are Q4 / Q5 / Q6 (storage / deletion / defaults) — only Q1 / Q7 / Q8 block the domain model.

### 00:02–00:12 — Semantics block (Q1 to Q3)

| # | Decision |
|---|---|
| **Q1** — tag merging | union vs trust |
| **Q2** — listed vs unlisted precedence | always-win vs depends |
| **Q3** — unlisted tie-break | first-write-wins vs last-write-wins |

Each gets ~3 minutes. Scribe writes the decision and the reasoning in one line.

### 00:12–00:20 — Storage & lifecycle block (Q4 to Q6)

| # | Decision |
|---|---|
| **Q4** — attribution storage shape | JSON column vs audit table |
| **Q5** — source deletion policy | keep-with-flag vs strip |
| **Q6** — default priority out of the box | ship a default vs start empty |

Same format. These are lower-stakes — defer to technical lead's recommendation unless customer has a strong preference.

### 00:20–00:28 — UX block (Q7 to Q9)

| # | Decision |
|---|---|
| **Q7** — trust vocabulary | 4 buckets vs numeric vs customer-named |
| **Q8** — same-bucket tie-break | last-write-wins vs by creation date |
| **Q9** — default trust at migration | `Manual → Primary, rest → Medium` vs alternatives |

Let the UI lead show the dropdown mockup from the summary. Q7 often flips after people see it.

### 00:28–00:30 — Close

- Facilitator reads back the decision log aloud, one line per question.
- Scribe appends the decision log to the RFC (commit same day).
- Action items assigned with names + due dates.
- No AOB. Any additional items go to email / next sync.

## Decision log template

Committed to the bottom of `asset-source-priority.md` after the meeting.

```markdown
## Decision log

Meeting held YYYY-MM-DD, decisions locked by <names>.

| # | Question | Decision | Reason |
|---|---|---|---|
| 1 | Tag merging | ... | ... |
| 2 | Listed vs unlisted | ... | ... |
| 3 | Unlisted tie-break | ... | ... |
| 4 | Attribution storage | ... | ... |
| 5 | Source deletion | ... | ... |
| 6 | Default priority | ... | ... |
| 7 | Trust vocabulary | ... | ... |
| 8 | Same-bucket tie-break | ... | ... |
| 9 | Migration defaults | ... | ... |

**RFC status**: Draft → Accepted. Phase 1a cleared to start YYYY-MM-DD.
```

## Escape hatches

The meeting is not the only forum. If any of these happen, stop the meeting and reschedule:

- Customer attendee changes (the new person has no context).
- A question opens up an unknown (e.g., "we actually use 11 data sources, not 3"). Update the RFC first.
- More than 2 questions hit the parked queue. The RFC is not ready.

## Out of scope for this meeting

Explicitly:

- Phase 2 features (per-field rules, policy engine, reprocessing). Send to a separate planning session.
- Pricing / licensing implications.
- UI color / copy / icon debates. Those go to the design PR.
- "Can we also add X while we're at it?" No. Scope discipline.

## Follow-up (within 24h of meeting)

1. RFC updated with decision log — commit + push.
2. RFC status badge flipped to `Accepted`.
3. Phase 1a branch created (`feat/asset-source-settings-domain`).
4. Parked items (if any) opened as separate RFC addenda or GitHub discussions.
5. Calendar hold for Phase 1a demo (~2 days after start).
