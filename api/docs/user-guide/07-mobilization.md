# Mobilization

**CTEM Stage 5.** Turning prioritized, validated exposures into fixed problems —
the part that actually reduces risk. This is where you assign work, push tickets
to your engineering trackers, enforce SLAs, and handle exceptions. These pages
live under the **Mobilization** sidebar section.

## Remediation campaigns

**Mobilization → Remediation** (`/remediation`) is the hub. A **campaign** groups
related findings into a coordinated fix effort with tasks.

- **Create a campaign**, then work its tasks.
- On a task, **Create Jira Epic** to push it to Jira (once linked, the button
  becomes **View Jira Epic ({key})**). Ticketing must be configured first — see
  [Settings & Integrations](09-settings-and-integrations.md#ticketing).
- **Export CSV** / **Export JSON** for reporting or hand-off.
- Filter by priority/status, use the **bulk actions** dropdown to move several
  tasks to In Progress / Review / Completed at once, and open a task drawer to
  edit fields inline.

### Solution Families

**Mobilization → Remediation → Solution Families** (`/remediations`) groups
findings that share a single fix (e.g. "upgrade library X"). For a group you can
**Track as campaign** or **Resolve all** at once — fixing the root cause instead
of closing findings one by one.

## Workflows

**Mobilization → Workflows** (`/workflows`) automates repetitive response steps.
Build a workflow visually (e.g. "Critical Finding Response") from action nodes —
including a **Create Jira Ticket** node — then **Run** it or edit it in the
builder. You can duplicate and delete workflows too.

## Scan Pipelines

**Mobilization → Scan Pipelines** (`/pipelines`) chains scanning and processing
steps into a repeatable pipeline. **Create** a pipeline, **trigger a run**, clone
or edit it, and open a run to see its detail. (There's also a visual pipeline
builder.)

## SLA compliance

Two related places:

- **Settings → SLA Policies** (`/settings/sla-policies`) is where you **define**
  SLAs. The **default policy** applies to every finding:
  - a finding with a priority class (P0–P3) gets its deadline from the
    priority window (platform defaults: P0 2 days, P1 5, P2 15, P3 30);
  - a finding without a class yet uses its severity window;
  - the finding turns **warning** once the policy's "warning at" percentage of
    its window has passed, and **overdue** at the deadline;
  - **Deadline notifications** (on by default) decide whether the warning and
    the breach are sent to your notification channels; the status changes
    either way.

  Without a policy the platform defaults apply. Saving a policy changes
  deadlines computed from then on, not deadlines already set.
- **Mobilization → SLA Compliance** (`/sla`) is where you **monitor** them — a
  live view of breaches and aging open findings by severity. (This page reports
  status; it doesn't configure SLAs.)

## Exceptions

**Mobilization → Exceptions** (`/exceptions`) handles findings you've decided not
to fix right now (accepted risk, false positive, compensating control in place).
Create an exception/suppression rule, then it moves through an approval flow:
**approve** or **reject** (with a reason). You can also edit or delete rules.

- Someone other than the requester approves the rule, unless the owner is the
  only person who can approve (that self-approval is recorded as a Critical
  audit event).
- If the rule is edited after you opened it, approving fails; reload and review
  the current version.
- When a rule expires or is deleted, the findings it hid return to the open
  backlog (unless another active rule covers them).

## Progress

**Mobilization → Progress** (`/progress`) is a read-only rollup of resolution
rate, status mix, and trend, with generated action items — a quick answer to
"how are we doing at actually closing things out?"
