# RFC-065: Bug-bounty programs, authorization sources and the Researcher role

| | |
|---|---|
| Status | Proposed (2026-10-09) |
| Scope | api (`pkg/domain/bountyprogram`, `pkg/domain/scope`, `internal/app/bountyprogram`, `internal/app/scopeauth`, `internal/app/actscope`, `internal/app/scan`, handlers, migrations), web (Programs area) |
| Architecture | [bounty-programs.md](../architecture/bounty-programs.md), [active-probe-gate.md](../architecture/active-probe-gate.md) |
| Related | RFC-054 (scope model: one authority check, guardrails, approvals), RFC-050 (data scope), RFC-040 (platform-sensor distrust), RFC-060 (tool overrides: headers, User-Agent, rate) |

## 1. Summary

People who test systems they do not own, under a program's published rules,
need to authorize targets differently from an organization scoping its own
estate. RFC-054 asks for ownership-style approvals on every widening; for a
researcher that is friction without safety, because the authority is the
program's published scope, not a colleague's second click.

This RFC keeps the single authority check of RFC-054 and adds:

1. **An authorization source on every scope entry**: `ownership`,
   `program`, `authorization_letter`, `self_attestation`. The entry still has
   to cover the target; the source decides how the entry comes into effect
   and where its traffic may come from.
2. **Programs**: a bug-bounty or disclosure program a person follows. One
   import (paste the program's scope list or its CSV export) creates the
   in-scope entries, the program exclusions for out-of-scope items and the
   program's rules. The program's entries take effect on the importer's **audited
   attestation**, bound to a hash of exactly what they accepted; no second
   approver.
3. **A built-in Researcher role**: works with programs and their targets,
   never widens ownership scope and never approves anything. Owners and
   administrators hold every program permission, so a one-person organization
   works with zero setup. Organizations use the same role for an internal red
   team or for staff hunting on partner programs. There is no "researcher
   organization" type.
4. **Program data scope**: each program has a group; its members see the
   program's assets and findings through the existing data-scope model.
5. **Operator protection**: program entries are never scanned from platform
   sensors (a pasted scope is not authoritative, and a program's safe harbour
   covers the researcher, not the infrastructure that sends the traffic).
6. **A scope snapshot per scan run**: the entries, exclusions and program
   attestations in force when the run started, stored with a SHA-256 hash.

## 2. Threat model

| Actor | Goal | Control |
|---|---|---|
| Overlapping program | a program lists as out of scope a name the organization owns, and its import silently stops the organization's own scans | program exclusions bind only `program` entries; the overlap is shown (B7) |
| Malicious tenant | pastes a "program" for a victim's domain and scans it | own sensors only (traffic leaves the tenant's infrastructure, not the operator's); platform deny list, public-suffix refusal, CIDR caps (RFC-054 §8); attestation with program URL in the audit log; T2 unreachable (needs proof of ownership) |
| Researcher member | widens the organization's own scope or approves an entry | the Researcher role has no `scope:write` / `scope:approve`; program routes create only `program` entries; general routes refuse widening changes to a program entry |
| Researcher member | sees the organization's inventory or another program's findings | data scope: program group membership only (RFC-050 Layer 2); program lists, details and covers are filtered by membership; cross-program isolation tests |
| Compromised session | imports a program and scans at once | step-up on import, re-import and resume; attestation names the person; every administrator notified |
| Careless importer | accepts a scope that changed after preview | the attestation carries the terms hash from the preview; the server recomputes it and refuses a mismatch (`PROGRAM_TERMS_CHANGED`) |
| Program shrinks its scope | removed assets keep being scanned | re-import (sync) deletes the entries of removed items at once; pause/end deactivates every entry of the program |
| Abuse desk / program owner | asks what was authorized when a run sent traffic | scope snapshot per run (hash + body), attestation audit events |
| Cross-tenant oracle | learns another tenant follows a program | every query is tenant-scoped; nothing is shared between tenants |

Every query is tenant-scoped (`tenant_id` from the authenticated context);
every lookup error refuses.

## 3. Decisions

| # | Decision |
|---|---|
| B1 | Authorization source per scope entry: `ownership` (default, existing rows), `program`, `authorization_letter` (P1), `self_attestation` (an internal or on-premises statement; same approvals as ownership) |
| B2 | Approval rules are keyed by the source, not the tenant: `ownership` and `self_attestation` follow the tenant's approval policy (RFC-054 §7); `program` needs only the creator's attestation; `authorization_letter` needs the uploaded letter and an expiry, plus approvals when the tenant's policy asks for them (P1) |
| B3 | "Researcher" is a built-in, customizable role (clone it to change it), assignable to users and through groups; never a tenant mode |
| B4 | A researcher sees only the assets and findings of the programs they belong to (program group); full-data roles see everything |
| B5 | Program entries are never routed to platform sensors until a program's scope comes from an authoritative source (P2) |
| B6 | Program entries authorize at most T1; T0 only when the program forbids automated scanning |
| B7 | Out-of-scope items become **program exclusions**: they stop every `program` entry of the tenant (all programs, all researchers) from covering the name, and so act scope for program members; `ownership`, `self_attestation` and `authorization_letter` entries are not affected. An overlap (a name out of scope for a program but in scope by ownership) is shown to administrators |
| B8 | A wildcard `*.x` whose apex `x` the program does not list in scope gets a program exclusion of exactly `x` (the strict reading of a program's wildcard; RFC-054 S1 reads `*.x` as including `x`) |

## 4. Authorization source

`scope_targets.authorization_source` (text, not null, default `ownership`)
and `scope_targets.program_id` (uuid, null; tenant-composite foreign key to
`bounty_programs`). A `program` entry has a `program_id`; no other source has
one.

| Source | Created by | Comes into effect | Platform sensors | Max tier |
|---|---|---|---|---|
| `ownership` | `POST /scope/targets` (RFC-054) | tenant approval policy | under `SCOPE_ACTIVE_PROOF` (RFC-054 §8.1) | entry's `max_tier` |
| `self_attestation` | `POST /scope/targets` with `authorization_source` | tenant approval policy | as `ownership` | entry's `max_tier` |
| `program` | programs routes only (§6) | the creator's attestation of the program's current terms | never (P0–P1) | `t1` (`t0` if the program forbids automated scanning) |
| `authorization_letter` | P1 | letter + expiry (+ approvals per policy) | as `ownership` | entry's `max_tier` |

The general routes refuse `authorization_source: program`
(`PROGRAM_ENTRY_VIA_PROGRAMS`) and refuse widening a program entry
(`activate`, a later expiry, a higher tier: `409 PROGRAM_MANAGED`). Narrowing
a program entry (deactivate, delete) works as for any entry. Every response
carries `authorization_source` and `program` (`{id, name}`) for a program
entry.

The authority check (RFC-054 §4.2) does not change: a program entry is an
ordinary entry while it is active. The scope join (§4.3) confirms discovered
names under a permanent program wildcard, so a researcher's recon lands in the
inventory of that program.

## 5. Programs

### 5.1 Data model (migration `001410`)

`bounty_programs`:

| Column | Type | Meaning |
|---|---|---|
| `id`, `tenant_id` | uuid | tenant-composite key |
| `name` | text ≤ 200 | unique per tenant (case-insensitive) |
| `platform` | text ≤ 50 | free label (where the program is run) |
| `handle` | text ≤ 100 | the researcher's handle on that program |
| `program_url` | text ≤ 500 | `https://` link to the program's policy and scope |
| `status` | `active`, `paused`, `ended` | |
| `scope_source` | `paste` | P1 adds `program_api`, `program_file` |
| `authoritative` | bool, false | P2: scope fetched from an authoritative source |
| `rules` | jsonb | §5.3 |
| `scope_items` | jsonb | the parsed paste (§5.2), including items no scan can target |
| `terms_sha256` | text | hash of the terms in force (§5.4) |
| `accepted_by`, `accepted_at` | uuid, timestamptz | the attestation in force |
| `group_id` | uuid | the program's group (data scope, §7) |
| `created_by`, `created_at`, `updated_at` | | |

`bounty_program_exclusions (tenant_id, id, program_id, target_type, pattern,
reason, created_at)`: the program exclusions (§5.2), tenant-composite keys,
deleted with their program.

### 5.2 Scope import

The person pastes the program's scope as text or as the program's CSV/TSV
export (header with `identifier` or `asset_identifier`, optional
`asset_type` and `eligible_for_submission` / `in_scope`; a false value is out
of scope). Text: one target per line, `In scope` / `Out of scope` headings,
a leading `-` or `!` marks out of scope, `#` comments, list bullets dropped.
At most 256 KiB and 2 000 items.

Each item becomes:

| Item | Entry or program exclusion |
|---|---|
| `*.example.com` | domain `*.example.com`; plus a program exclusion of `example.com` unless it is listed in scope (B8) |
| `example.com`, `https://example.com/` | domain `example.com` |
| `https://example.com/api/*` | url `https://example.com/api*` (path-limited) |
| `192.0.2.10`, `192.0.2.0/24`, `a-b` | ip_address, cidr, ip_range |
| app ids, source code, hardware, executables, free text, `api-*.example.com` | not scannable: kept on the program and shown, never an entry |

Out-of-scope items become **program exclusions**
(`bounty_program_exclusions`: program, type, pattern), in effect while the
program exists. They are not RFC-054 exclusions: the dispatch gate and the
organization's own entries never see them. The authority check reads them
when it weighs `program` entries: a name a program exclusion matches is not
covered by any `program` entry of the tenant (all programs, all researchers;
fail-safe), while an `ownership`, `self_attestation` or `authorization_letter`
entry still covers it. The program detail lists each program exclusion with
the organization's own entry that covers it, if any ("in scope by
ownership"), so an administrator sees the overlap.

### 5.3 Rules

```json
{ "rate_limit_rps": 5,
  "required_headers": [{"name": "X-Bug-Bounty", "value": "jdoe"}],
  "user_agent": "jdoe-research",
  "forbidden": ["dos", "automated_scanning", "social_engineering", "physical", "bruteforce", "intrusive"],
  "notes": "free text from the policy" }
```

Bounds: `rate_limit_rps` 0–1000 (0 = none stated); at most 10 headers, name a
token of at most 64 characters, value at most 200, no control characters;
`user_agent` at most 200; `notes` at most 4 000. P0 enforces `forbidden:
automated_scanning` (entries at `t0`) and never allows `t2`; the rate cap,
headers and User-Agent reach the sensor through the tool overrides of RFC-060
in P1.

### 5.4 Terms and attestation

The **terms** are the canonical JSON of `{program_url, rules, in_scope,
out_of_scope}` (items sorted); `terms_sha256` is its SHA-256. The preview
returns it. Creating, re-importing and resuming a program require
`accept_terms_sha256` equal to the hash the server computes for the request
(`PROGRAM_TERMS_CHANGED` otherwise) and step-up. The attestation records
`accepted_by`, `accepted_at`, the hash and the program URL, and is audited
(`bounty_program.terms_accepted`); every administrator is notified. This
replaces the second approver for program entries (B2).

### 5.5 Lifecycle

- **Import** (`POST /programs`): program + group + entries + program exclusions in one
  transaction; the importer joins the group.
- **Re-import / sync** (`PUT /programs/{id}/scope`): the new paste replaces
  the old; entries and program exclusions of items no longer listed are deleted at
  once; new ones are created; a new attestation is required.
- **Pause** (`POST /programs/{id}/pause`): every entry of the program becomes
  `inactive` (narrowing, no step-up). **Resume** re-activates them with a new
  attestation. **End** deactivates them for good; the program stays for its
  history.

## 6. API (`/api/v1/programs`, module `scope_config`)

| Route | Permission | Notes |
|---|---|---|
| `GET /` | `attack_surface:programs:read` | members see their programs; full-data callers see all |
| `POST /preview` | `attack_surface:programs:write` | parse + guardrails + `terms_sha256`; writes nothing |
| `POST /` | `attack_surface:programs:write` + step-up | `{name, platform, handle, program_url, scope_text, rules, accept_terms_sha256}` |
| `GET /{id}` | `programs:read` + member or full data | program, items, entries, program exclusions with their ownership overlaps, attestation |
| `PUT /{id}/scope` | `programs:write` + member or full data + step-up | re-import |
| `POST /{id}/pause`, `/end` | `programs:write` + member or full data | narrowing |
| `POST /{id}/resume` | `programs:write` + member or full data + step-up | `{accept_terms_sha256}` |
| `GET /scans/runs/{id}/scope-snapshot` | `scans:read` + run in data scope | §9 |

A program the caller may not see answers 404. Errors: `PROGRAM_SCOPE_EMPTY`,
`PROGRAM_SCOPE_TOO_LARGE`, `PROGRAM_TERMS_CHANGED`, `PROGRAM_NAME_TAKEN`,
`PROGRAM_NOT_ACTIVE`, `PROGRAM_ENDED`, plus the RFC-054 codes.

## 7. Researcher role and data scope

Permissions `attack_surface:programs:read` and
`attack_surface:programs:write` (owner and admin by default). The system role
**Researcher** (`researcher`, fixed id `00000000-0000-0000-0000-000000000005`,
no full data access) holds: `dashboard:read`, `assets:read`,
`findings:read|write|status|triage|export`, `scans:read|write|execute`,
`scans:profiles:read`, `scans:templates:read`, `scans:workflows:read`,
`sensors:read`, `attack_surface:programs:read|write`. It holds no scope,
sensor-management, member or settings permission. Organizations clone it to
change it.

**Data scope.** Each program has a group (type `project`, created with the
program). Program members are the group's members, added like any group
member (users directly; a team by adding its people). A program assignment
pass keeps `asset_owners` rows (`assignment_source = 'program'`) for every
tenant asset the program's active entries cover and removes the others; the
existing trigger maintains `user_accessible_assets`. The pass runs after
import, re-import, pause, resume and end, after each scope join (every scope
change and every 6 h), and after scan results land.

**Act scope.** A restricted member may also scan typed targets that an
active entry of a program they belong to covers (RFC-054 §4.2 still runs in
full). Everything else stays as RFC-050 D9.

## 8. Platform sensors

The trigger refuses platform sensors for a target that only `program`
entries cover: an explicit `sensor_preference: platform` answers `400
PLATFORM_SENSOR_REFUSED` naming the targets; `auto` keeps the job on the
tenant's sensors. A target an `ownership` entry also covers is unaffected.
This holds in every `SCOPE_ACTIVE_PROOF` mode. P2 lifts it for authoritative
programs, with per-program quotas, an abuse contact, a kill switch per
program and target, and researcher terms of use.

## 9. Scope snapshot per run

When a scan run is created, the scope in force (in-effect entries with their
source, program and tier; in-effect exclusions; program exclusions; active programs with
`terms_sha256`, `accepted_by`, `accepted_at`) is serialized canonically and
hashed. `scope_snapshots (tenant_id, sha256, body)` stores each distinct
body once; `scan_run_scope_snapshots (tenant_id, run_id, sha256, taken_at)`
links the run. `GET /api/v1/scans/runs/{id}/scope-snapshot` returns
`{sha256, taken_at, body}`. A failed snapshot write is logged and noted on
the run; it does not stop the run.

## 10. Plan

| Phase | Items |
|---|---|
| P0 | authorization source; programs with paste/CSV import, preview, attestation, program exclusions, re-import, pause/resume/end; Researcher role; program data scope and act scope; platform sensors refused for program entries; scope snapshot per run; web Programs area |
| P1 | sync from program APIs with the researcher's own tokens (per-tenant encrypted credentials) and scope files a program publishes; rules enforced by the engine (rate cap, headers, User-Agent, testing windows); `authorization_letter` with uploaded letter; one entry shared by several programs |
| P2 | platform sensors for authoritative programs with quotas; abuse workflow (contact page, per-program and per-target kill switch, opt-out registry); researcher terms of use |

## 11. Implementation (P0)

| PR | Content |
|---|---|
| Docs | this RFC, index, architecture |
| Model | migration `001410` (programs, source, snapshot tables, permissions, Researcher role); domain types, parser, terms hash |
| Programs | service + routes: preview, import, re-import, pause/resume/end, attestation audit, notification |
| Gate | platform-sensor refusal for program entries; act scope for program members; program assignment pass |
| Snapshot | snapshot per run + route |
| Web | Programs area (list, import with preview and attestation, detail with scope, rules, snapshots) |
