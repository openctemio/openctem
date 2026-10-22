# Bug-bounty and disclosure reports

Design: [RFC-121](../rfcs/RFC-121-bug-bounty-reports.md). Related:
[finding import](finding-import.md), [deduplication](deduplication.md),
[authorization matrix](authorization-matrix.md) (data scope),
[finding retest checks](finding-retest-checks.md),
[bug-bounty programs](bounty-programs.md) (the hunter side, RFC-065).

An organisation that runs a bug-bounty program or a disclosure program keeps
receiving reports on its own channel. OpenCTEM files each report as a
**finding with source `bug_bounty`** and a typed report object, so the
finding lifecycle (asset, owner, SLA, remediation task, ticket, retest check,
dashboards, data scope) applies with no second workflow. OpenCTEM does not
pay rewards, hold researcher accounts or message researchers.

## Flow

```
report on the program's channel
        │  (export file today; signed webhook later)
        ▼
ctis importer "bounty_report" (JSON / CSV, pure, no network)
        │
        ▼
finding (source bug_bounty) + metadata.bounty_report
        │  unique (tenant, intake, ref): a re-import updates the same row
        ▼
triage ── GET /findings/{id}/duplicate-candidates (caller's data scope)
        │        "known internally since <first_detected_at>"
        ├── mark duplicate of (existing, person decides)
        └── confirm ─► remediation task ─► SLA ─► retest check ─► resolved
```

## The report object

`metadata.bounty_report` on the finding, returned on finding reads as
`bounty_report`. Fields and rules: RFC-121 §3. In short:

- identity: `intake` (the channel) and `ref` (its report id), fixed once set,
  unique per organisation among `bug_bounty` findings;
- researcher: a **handle** only (no email, no name);
- `reported_severity` is the reporter's claim; the finding's own severity is
  assessed by the triager and priority comes from the normal pipeline;
- `state` is the channel's state of the report and never moves the finding's
  status (human sources are never closed by automation);
- `url` is an https back-link that the server never fetches;
- `reward` and `disclosure` are data; changing them needs `findings:triage`
  and writes an audit row with the old and new values.

## Authorization and isolation

| Action | Gate | Isolation |
|---|---|---|
| Create a `bug_bounty` finding with a report | `findings:write` (+ `findings:triage` for reward or disclosure) | Tenant from the session; the asset must be in the caller's data scope |
| Replace the report object | `findings:write` (+ `findings:triage` when reward or disclosure changes) | Finding in the caller's data scope, else 404 |
| Duplicate candidates | `findings:triage` | Seed finding in the caller's data scope, else 404 (also for another tenant's id); candidates filtered with the findings-list scope rules |

Reporter text is untrusted: it is stored as data, rendered only through the
markdown sanitiser, and `bug_bounty` findings are never sent to AI triage
automatically (RFC-121 D13).

## Status

| Part | State |
|---|---|
| RFC and this page | Done |
| Report value object and the unique index | Designed |
| Report fields on create and update (triage gate, audit) | Designed |
| ctis `bounty_report` converter (JSON, CSV) | Designed |
| Duplicate candidates endpoint | Designed |
| Web Report section and candidates panel | Designed |
| Programme saved view and dashboard tiles | Designed |
| Signed webhook intake, invited hunters, scope export, public form | Later (RFC-121 §8) |
