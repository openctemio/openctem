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

### Storage and identity

- `vulnerability.BountyReport` validates and normalises the object
  (`Normalized`, `Validate`); `Finding.SetBountyReport` stores it only on a
  `bug_bounty` finding and refuses a change of `intake` or `ref`;
  `Finding.BountyReport` reads it back.
- The partial unique index `idx_findings_bounty_report_ref` on
  `findings (tenant_id, metadata->'bounty_report'->>'intake',
  metadata->'bounty_report'->>'ref') WHERE source = 'bug_bounty'` makes a
  second finding for the same report a conflict
  (`vulnerability.ErrBountyReportExists`, HTTP 409) on create and update.
  Findings of other sources are outside it.
- `FindingRepository.FindByBountyReport(tenant, intake, ref)` is the lookup a
  re-import or a webhook delivery uses to update the same row.

## Authorization and isolation

| Action | Gate | Isolation |
|---|---|---|
| Create a `bug_bounty` finding with a report | `findings:write` (+ `findings:triage` for reward or disclosure) | Tenant from the session; the asset must be in the caller's data scope |
| Replace the report object | `findings:write` (+ `findings:triage` when reward or disclosure changes) | Finding in the caller's data scope, else 404 |
| Duplicate candidates | `findings:triage` | Seed finding in the caller's data scope, else 404 (also for another tenant's id); candidates filtered with the findings-list scope rules |

Reporter text is untrusted: it is stored as data, rendered only through the
markdown sanitiser, and `bug_bounty` findings are never sent to AI triage
automatically (RFC-121 D13).

## Duplicate candidates

`GET /api/v1/findings/{id}/duplicate-candidates` (`findings:triage`) works
for any finding; for a bounty report it adds the report's CWE and endpoint
path to the signals and compares dates with its `submitted_at`.

- **Candidates:** other findings of the tenant, not folded duplicates, any
  source and status (resolved included), on the same asset or on an asset
  whose name has the same host (`assetHostSQL`), and sharing a CWE, a CVE or
  a vulnerable path (the report's `endpoint_path` and the finding's own
  injection points against the candidate's injection points).
- **Order:** same asset first, then the number of matching signals, then the
  earliest first detection. At most 20.
- **Scope:** the seed finding is checked first (404 outside the caller's
  scope or tenant); candidates are filtered in SQL with the caller's data
  scope and the pentest member rule, so `known_since` is computed only from
  findings the caller can read.

Response (contract for the web candidates panel):

```json
{
  "finding_id": "…",
  "report_submitted_at": "2026-10-21T09:00:00Z",
  "known_since": "2026-09-22T17:00:00Z",
  "known_before_report": true,
  "candidates": [
    {"finding_id": "…", "title": "…", "source": "dast", "status": "confirmed",
     "severity": "high", "asset_id": "…", "asset_name": "shop.example.com",
     "first_detected_at": "2026-09-22T17:00:00Z",
     "matched_on": ["same_asset", "cwe"], "known_before_report": true}
  ],
  "limit": 20
}
```

`report_submitted_at`, `known_since` and the `known_before_report` fields are
omitted when there is nothing to compare. The person then uses
`POST /api/v1/findings/{id}/duplicates` (same asset only) or keeps both.

## Status

| Part | State |
|---|---|
| RFC and this page | Done |
| Report value object and the unique index | Done (`pkg/domain/vulnerability/bounty_report.go`, migration `findings_bounty_report_ref_unique`) |
| Report fields on create and update (triage gate, audit) | Designed |
| ctis `bounty_report` converter (JSON, CSV) | Designed |
| Duplicate candidates endpoint | Done (`GET /api/v1/findings/{id}/duplicate-candidates`) |
| Web Report section and candidates panel | Designed |
| Programme saved view and dashboard tiles | Designed |
| Signed webhook intake, invited hunters, scope export, public form | Later (RFC-121 §8) |
