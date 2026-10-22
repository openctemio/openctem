# RFC-121: Bug-bounty and disclosure reports as findings

| | |
|---|---|
| Status | Accepted (2026-10-22). Being implemented in small steps; `docs/architecture/bounty-reports.md` says what is built |
| Scope | api (`pkg/domain/vulnerability` report value object, `internal/app/finding`, findings handlers, one migration), ctis `importer` (generic report converter), web (finding Report section, duplicate candidates, programme tiles) |
| Architecture | [bounty-reports.md](../architecture/bounty-reports.md) |
| Related | RFC-065 (people who hunt on outside programs; this RFC is the other side: an organisation receiving reports), RFC-043 (deduplication and "mark duplicate of"), RFC-050 (data scope), RFC-119 (AI triage governance), RFC-058 (outside members) |

## 1. Summary

An organisation that runs a bug-bounty program or a vulnerability disclosure
program (VDP) receives reports from outside researchers on a third-party
service or by its own channel. OpenCTEM does not become that service. It
brings each report into the CTEM loop as a **finding with source
`bug_bounty`**, so the report sits on the right asset, next to scanner
history, with an owner, an SLA, a remediation task, a ticket and a retest,
and so triage can answer "did we already know this, and since when?" from
our own first-seen data before a reward is decided.

Payouts, tax and identity checks, researcher reputation, mediation and a
researcher marketplace are out of scope: they are a business of their own
and every organisation that pays rewards already has a service for them.

## 2. Decisions

| # | Decision |
|---|---|
| D1 | Integrate reports into the CTEM loop; never build a bounty platform (payments, researcher accounts, messaging). |
| D2 | A report is a finding with source `bug_bounty` and a typed report object (§3). Every finding feature (asset, SLA, tasks, tickets, retest checks, dashboards, data scope) applies with no copy. Invited hunters inside OpenCTEM (later) use a pentest campaign kind that writes source `bug_bounty`. |
| D3 | One report, one finding: a partial unique index on `(tenant_id, intake, ref)` for `bug_bounty` findings. A re-import or a replayed delivery updates the same row; human findings keep their own fingerprint rules. |
| D4 | Duplicates are **suggested**, never merged automatically. Candidates come from the caller's data scope only; the person uses the existing "mark duplicate of" action. The candidate's first-detected date is shown against the report's submission date ("known internally since"). |
| D5 | Intake order: file import first; a signed webhook next; pulling from a bounty service's API is not planned; a hosted public form only later, opt-in, after its own threat review; inbound email never. |
| D6 | One documented generic intake schema (JSON and CSV, §4) read by one converter in the shared importer library. No per-service formats. |
| D7 | The reporter's severity is kept as data (`reported_severity`). The finding's severity is ours: the triager assesses it, and priority comes from the normal pipeline (CVSS, asset criticality, exposure). The difference is a triage signal, not an input to risk. |
| D8 | The researcher is a **handle** only. No email or name is stored by import or the API. (A public form, if ever built, stores an email encrypted, write-once, shown to triagers only and erased on schedule.) |
| D9 | Reward and disclosure are **fields**, not a workflow: `reward {amount, currency, status}` and `disclosure {state, agreed_date}`. Changing either needs `findings:triage` and is audited with the old and new values. |
| D10 | Invited hunters (later): a pentest campaign of kind `bounty` with outside members whose access must end; a hunter sees only their own drafts and findings. |
| D11 | Publishing a program scope (later): export only explicit scope entries tagged for the program, never discovered inventory; step-up and audit. |
| D12 | A hosted public intake form (later): opt-in per organisation, unguessable rotatable slug, CAPTCHA and three rate-limit levels, an inbox separate from findings, identical response for every outcome. |
| D13 | Reporter text is untrusted. `bug_bounty` findings are **never AI-triaged automatically**; a person may ask for it, and the prompt marks the text as untrusted data with no tool calls or automatic actions from the result. |

## 3. The report object

Stored on the finding at `metadata.bounty_report` and returned on finding
reads as `bounty_report`. Validated by `vulnerability.BountyReport` on every
write (API and import), with these rules:

| Field | Type | Rules |
|---|---|---|
| `intake` | string | Required. Names the channel the report came from (a program, a VDP, later a webhook integration). 1–64 chars of `a-z 0-9 . _ -`, starts with a letter or digit. Fixed once set. |
| `ref` | string | Required. The report's id in that channel. 1–128 printable ASCII chars without spaces. Fixed once set. |
| `researcher` | string | Handle only, ≤ 64 chars, one line, control and bidirectional-override characters refused. |
| `submitted_at` | RFC 3339 time | When the researcher submitted it; not more than one day in the future. |
| `reported_severity` | enum | `critical`, `high`, `medium`, `low`, `info`, `none`: what the reporter claimed. |
| `state` | enum | The channel's state of the report: `new`, `triaged`, `duplicate`, `informative`, `not_applicable`, `resolved`. Never moves the finding's status. |
| `weakness` | string | `CWE-<n>`. |
| `endpoint_path` | string | The vulnerable path on the asset, starting with `/`, ≤ 1024 chars, no scheme or host. |
| `parameter` | string | The vulnerable parameter, ≤ 128 chars. |
| `url` | string | Back-link to the report on its channel. `https` only, a host, no user info, ≤ 2048 chars. Never fetched by the server; rendered as a safe external link. |
| `reward` | object | `amount` (decimal string, ≥ 0, ≤ 12 integer digits, ≤ 2 decimals), `currency` (ISO 4217 code), `status` (`none`, `pending`, `paid`). |
| `disclosure` | object | `state` (`private`, `coordinated`, `disclosed`), `agreed_date` (`YYYY-MM-DD`). |

Identity: `(tenant_id, intake, ref)` is unique among `bug_bounty` findings
(D3). The tenant always comes from the authenticated context, never from the
report.

## 4. Generic intake schema (import)

One record per report; JSON (`{"bounty_reports": [ ... ]}`) or CSV with a
header row of the same names (nested fields flattened as `reward_amount`,
`reward_currency`, `reward_status`, `disclosure_state`,
`disclosure_agreed_date`). The file format name is `bounty_report`; CSV is
read only when that format is chosen.

| Field | Meaning |
|---|---|
| `report_ref` | The report id (required). |
| `intake` | Optional per record; otherwise the import's intake. |
| `title` | Required, one line. |
| `submitted_at`, `researcher`, `reported_severity`, `state`, `weakness`, `cvss_vector`, `url`, `reward`, `disclosure` | As in §3. |
| `asset` | Host, URL or application id the report is about. A URL is split into host (the asset) and path (`endpoint_path`). |
| `parameter` | As in §3. |
| `description` | Markdown, ≤ 64 KB. |
| `steps`, `impact` | Markdown, ≤ 64 KB and ≤ 16 KB. |

The converter is a pure function: it never resolves names, fetches a URL or
opens a connection, whatever the input says.

## 5. API

| Method and path | Gate | Behaviour |
|---|---|---|
| `POST /api/v1/findings` with `bounty_report` | `findings:write`; `findings:triage` too when `reward` or `disclosure` is set | Only with `source = bug_bounty`. A second finding with the same `(intake, ref)` is a 409. |
| `PUT /api/v1/findings/{id}/bounty-report` | `findings:write`; `findings:triage` too when `reward` or `disclosure` changes | Replaces the report object of a `bug_bounty` finding in the caller's data scope. `intake` and `ref` cannot change once set. Audited with the old and new values of every changed field. |
| `GET /api/v1/findings/{id}/duplicate-candidates` | `findings:triage`; the finding must be in the caller's data scope (404 otherwise, also for another tenant's id) | Up to 20 candidates (§6), each with its `first_detected_at`, source, status and why it matched, plus the report's `submitted_at` and whether a candidate was known before it. |

## 6. Duplicate candidates

A candidate is another finding of the same tenant that is not a folded
duplicate and:

- sits on the same asset, or on an asset with the same host name, **and**
- shares a CWE, or a CVE, or the vulnerable path (the report's
  `endpoint_path` against the candidate's recorded injection points).

Any source and any status count, resolved included (a fixed issue reported
again is a regression or a duplicate claim). Candidates are computed inside
the caller's data scope with the same rules as the findings list (asset
scope rows, private program assets, pentest member visibility), so the
endpoint cannot be used to learn about findings the caller may not read.
Ordered by: same asset first, then the number of matching signals, then the
earliest first-detected date.

## 7. Threat model

Content arrives from people outside the organisation: through a file a
triager imports, later a relay webhook, later a public form.

| # | Threat | Control | Test |
|---|---|---|---|
| T1 | Stored XSS from report text in the console, reports, tickets, notifications | Text is stored as data; every render path sanitises markdown; tickets and notifications get plain text; length caps at intake | Hostile corpus in converter tests; web render tests (with the Report section) |
| T2 | SSRF or tracking through report links | The server never fetches reporter URLs; `url` is https only and shown as a safe external link; external images in markdown are not loaded | Converter test asserts zero outbound requests; value object refuses `http`, `file`, `gopher`, `javascript`, user info |
| T3 | A PoC turned into a request against an internal host | Retest checks only through the existing validator; nothing is generated from a raw PoC | Existing retest check tests |
| T5 | Flooding findings | Import is authenticated and rate limited; limits per file | Import limits |
| T7 | Duplicate-candidate oracle | Candidates joined to the caller's data scope like every finding read; the seed finding is checked first (404) | Restricted member and cross-tenant tests |
| T9 | A channel state closing our finding | `state` is report data only; human sources are never closed by automation | Value object and import tests |
| T11 | Researcher PII | Handle only; no email or name fields | Schema has none |
| T12 | Prompt injection through report text | No automatic AI triage for `bug_bounty` (D13) | Service test: creation does not enqueue AI triage |
| T14 | Report filed in the wrong tenant | Tenant from the authenticated context only | Handler tests |
| T15 | Reward or disclosure tampering | `findings:triage` to change them; audit row with old and new values | Authz and audit tests |

## 8. Delivery

Each step is one pull request with its tests, changelog fragment and docs.

1. This RFC and the architecture page.
2. The report value object and the unique index.
3. Report fields on create and update, with the triage gate and audit.
4. The generic report converter in the importer library (ctis).
5. Duplicate candidates.
6. Web: the finding Report section, candidates panel with "mark duplicate",
   import dialog format.
7. Programme views: saved view and pre-computed dashboard tiles (reports by
   state, valid %, duplicate %, known-internally %, time to triage and fix,
   reward totals by currency).

Later steps (signed webhook intake, invited hunters, scope export, disclosure
reminders, a public form) follow D5, D10, D11 and D12 and get their own
threat review before they are built.
