# RFC-065: Bug-bounty programs, authorization sources and the Researcher role

| | |
|---|---|
| Status | Proposed (2026-10-09); P0 in review; P1 designed (§12–§14, owner delegated 2026-10-09); private programs and the public program monitor added 2026-10-10 (§15–§16, owner direction), §15 in implementation |
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

### 5.1 Data model (migration `001495`)

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
token of at most 64 characters, value at most 200, no control characters, and
no credential or connection header (`Authorization`, `Cookie`, `Host`,
`Proxy-*`, `Content-Length`, `Transfer-Encoding`, `Connection`, …);
`user_agent` at most 200; `notes` at most 4 000; `testing_windows` (P1, §12)
at most 14. P0 enforces `forbidden: automated_scanning` (entries at `t0`) and
never allows `t2`; P1 enforces the rate cap, headers, User-Agent and testing
windows on every job (§12).

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
- **Suspend** (`POST /programs/{id}/suspend`): every entry of the program becomes
  `inactive` (narrowing, no step-up). **Reactivate** (`POST /programs/{id}/reactivate`) re-activates them with a new
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
| `POST /{id}/suspend`, `/end` | `programs:write` + member or full data | narrowing |
| `POST /{id}/reactivate` | `programs:write` + member or full data + step-up | `{accept_terms_sha256}` |
| `GET /api/v1/scan-runs/{id}/scope-snapshot` | `scans:read` + (`scope:read` or `programs:read`), run visible to the caller | §9 |

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
existing trigger maintains `user_accessible_assets`. Manual assignments of
the group are never touched. The pass runs after import, re-import,
suspend, reactivate and end, after scan results land, and every 30 minutes
(controller `program-assignment`), so assets that arrive by discovery are
covered too.

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

When a scan run is created, the authority its targets relied on is
serialized canonically and hashed: for each target, the entry that covered
it (id, type, pattern, authorization source, program, tier, expiry, approval
time), the programs those entries belong to with `terms_sha256`,
`accepted_by`, `accepted_at` and their program exclusions, and the number of
targets nothing covered. Identical authority gives the same hash.
`scope_snapshots (tenant_id, sha256, body)` stores each distinct body once;
`scan_run_scope_snapshots (tenant_id, run_id, sha256, taken_at)` links the
run (tenant-composite keys). `GET /api/v1/scan-runs/{id}/scope-snapshot`
(`scans:read` and `scope:read` or `programs:read`; a run the caller may not
see answers 404) returns `{sha256, taken_at, body}`. A failed snapshot is
logged and noted in the run's warnings; it does not stop the run.

## 10. Plan

| Phase | Items |
|---|---|
| P0 | authorization source; programs with paste/CSV import, preview, attestation, program exclusions, re-import, pause/resume/end; Researcher role; program data scope and act scope; platform sensors refused for program entries; scope snapshot per run; web Programs area |
| P1 | rules enforced at delivery: headers, User-Agent, rate cap, testing windows, conflicts (§12); authorization letters (§13); sync from the program API and from published scope files, narrowing at once and widening on acceptance (§14) |
| P2 | platform sensors for authoritative programs with quotas; abuse workflow (contact page, per-program and per-target kill switch, opt-out registry); researcher terms of use |

## 11. Implementation (P0)

| PR | Content |
|---|---|
| Docs | this RFC, index, architecture |
| Model | migration `001495` (programs, source, snapshot tables, permissions, Researcher role); domain types, parser, terms hash |
| Programs | service + routes: preview, import, re-import, pause/resume/end, attestation audit, notification |
| Gate | platform-sensor refusal for program entries; act scope for program members; program assignment pass |
| Snapshot | snapshot per run + route |
| Web | Programs area (list, import with preview and attestation, detail with scope, rules, snapshots) |

## 12. Rules enforcement (P1)

The program's rules are applied where every job leaves the platform: command
delivery (`command.Service.Poll` / `Claim`), next to the organization's tool
HTTP layer (RFC-060 §4.1). Every path that makes a scan command (single
scans, workflow steps, retests, validation, coverage) passes there, and the
rules in force at delivery apply, not the ones at creation.

For each scan command the platform finds the programs whose in-effect
entries cover the command's targets (program exclusions applied, the same
answer as `scopeauth`). Targets no program covers add no rule. Then:

| Rule | Effect on the delivered command |
|---|---|
| `required_headers` | added to `http_policy.headers` (sdk-go `core.OrgHTTPPolicy.Headers`); the tool host sends them on every request and they replace a `tool.yaml` header of the same name |
| `user_agent` | `http_policy.user_agent` (the program's wins over the organization's; a User-Agent forced by the sensor-local policy still wins) |
| `rate_limit_rps` | the command's `config.rate_limit` becomes the smallest of its own value and the programs' (the scanner reads it through `ScanOptions.RateLimit` and caps it at the sensor ceiling) |
| `testing_windows` | outside every window of a program, the command is not delivered; it waits and leaves when a window opens (since RFC-067 evaluated as a non-overridable scan window source) |

**Conflicts.** Two programs covering one command with different values for
the same header name, or different User-Agents, cannot both be honoured: the
command is not delivered and fails with `PROGRAM_RULES_CONFLICT` naming the
programs. The trigger refuses such a run up front (`PROGRAM_RULES_CONFLICT`,
400), so a person scans one program at a time; the delivery check is the
backstop for paths that do not go through the trigger.

**Testing windows** (`rules.testing_windows`): `[{"days": ["mon", …],
"start": "09:00", "end": "17:00", "timezone": "Europe/Paris"}]`, at most 14,
`end` after `start` (no overnight window; add two), IANA time zones only. No
window means any time. Since RFC-067 the windows are a source of the scan
window evaluator: a manual run outside them waits, a scheduled run is
deferred to the next opening (no longer skipped), a target whose windows
never open refuses the run (`SCAN_WINDOW_NEVER_OPENS`), and no override ever
lifts them.

Headers and User-Agent need sdk-go `core.OrgHTTPPolicy.Headers` (sdk-go
#227, #228); a sensor without it ignores the field, so a command that carries
a program's headers or User-Agent goes only to a sensor that reported SDK
v0.19.0 or later (`command.MinSDKForProgramHTTPRules`). Any other sensor,
including a development build or one that reported no version, does not get
it: the command waits, and a claim by id answers `PROGRAM_RULES_UNSUPPORTED`.
A rule lookup that fails withholds the command (fail closed). A program can
never require a credential or connection header (`Authorization`, `Cookie`,
`Host`, `Proxy-*`, `Connection`, …): the import refuses it.

## 13. Authorization letters (P1)

A letter of authorization (a pentest engagement, a client's written
permission) is uploaded once and named by the entries it authorizes.

- `authorization_letters (tenant_id, id, title, issuer, reference,
  valid_from, valid_until, attachment_id, file_sha256, uploaded_by,
  created_at, revoked_at, revoked_by)`; the file is stored through the
  attachment storage (PDF, PNG or JPEG, the attachment size limit) with
  context `authorization_letter`. `valid_until` is required, in the future
  and at most 2 years after `valid_from`.
- `POST /api/v1/scope/letters` (multipart, `attack_surface:scope:write`),
  `GET /api/v1/scope/letters`, `GET /api/v1/scope/letters/{id}/file`
  (`scope:read`), `POST /api/v1/scope/letters/{id}/revoke`
  (`scope:approve`, audited, administrators notified).
- An entry with `authorization_source: authorization_letter` names its
  `letter_id` (`scope_targets.letter_id`, tenant-composite key; the
  authorization source requires it and no other source has one). It goes
  through the tenant's approval policy like an ownership entry (B2).
- The entry authorizes only while its letter is valid (`valid_from` ≤ now <
  `valid_until`, not revoked): the read of in-effect entries joins the
  letter, so expiry and revocation stop scanning at once without a sweep.
- Intrusive (T2) probes still need proof (RFC-054 §8.1); a platform-reviewed
  letter as a proof kind is RFC-054 P1 and not part of this RFC.

## 14. Program sync (P1)

A program can keep its scope in sync with a source the program controls:

| `scope_source` | Where the scope comes from |
|---|---|
| `paste` | the person (P0) |
| `program_api` | the researcher scope API of the platform that runs the program (HackerOne's Hacker API: `GET /v1/hackers/programs/{handle}/structured_scopes`, in scope when `eligible_for_submission`, out of scope otherwise), with the researcher's own API token |
| `program_file` | a scope file the program publishes at an `https` URL on the program's own registrable domain (the text or CSV format of §5.2) |

- The API token is stored encrypted (`APP_ENCRYPTION_KEY`, fail closed when
  it cannot be decrypted), per program, never returned.
- Fetches go through the platform's outbound guard (`pkg/httpsec`: no
  private, loopback or metadata address), with a 256 KiB body limit and a
  30 s timeout. A failed fetch keeps the current scope and records the error.
- `POST /api/v1/programs/{id}/sync` (members or full-data callers,
  `programs:write`) and a controller every 6 h.
- **Narrowing applies at once:** an item that left the source loses its
  entry; a new out-of-scope item becomes a program exclusion; both audited
  (`bounty_program.synced`).
- **Widening waits for a person:** new in-scope items and changed rules
  make the program `needs_acceptance`: the new terms and their hash are kept
  as pending, members are notified, and nothing is added until a member
  accepts them (`POST /api/v1/programs/{id}/accept`, step-up, the pending
  terms hash) — the same attestation as an import.
- A program whose source says it is closed (the API's
  `submission_state` other than `open`, or the file gone for 7 days) is
  suspended automatically.
- `authoritative` stays false in P1: a synced scope still never reaches
  platform sensors (§8); P2 decides with quotas and the abuse workflow.

## 15. Private programs (addendum, 2026-10-10)

Most programs a researcher works on are private or invite-only. Their page,
scope table and terms sit behind the platform's login, and the link itself
can be confidential: asking for a fetchable link (§5, §14 `program_file`) does
not fit them. A private program is the organization's own CTEM work under
someone else's rules: scope entries, assets, scans, findings and approvals as
for any scope, plus only what a program adds.

### 15.1 Decisions

| # | Decision |
|---|---|
| P1 | `/programs/new` starts from a source: **Enter manually** (paste the scope list and fill the rules) or **Import file** (§15.2). Neither needs a link or a credential; `program_url` is optional |
| P2 | Never a browser session, a cookie or a scraped logged-in page: a session cookie is a whole-account credential the platform cannot scope or revoke for us, using it breaks the platforms' terms, and it breaks whenever the page changes |
| P3 | A program has a `visibility`: `private` (default for new programs) or `public`. Programs that existed before keep today's behaviour (`public`) |
| P4 | A private program, its scope entries, rules, terms and link are visible only to members of its group and to the organization's **owners**. Administrators and full-data roles who are not members get 404, like another tenant |
| P5 | Each person accepts a private program's terms and confidentiality before seeing its details; the acceptance is bound to the program's `terms_sha256`, so a change of terms asks everyone again |
| P6 | Every view of a private program is audited (`bounty_program.viewed`); audit events of a private program never carry its link |
| P7 | A per-user researcher API connector (the person's own API token for the platform that runs the program) is a later option, not P0 |

### 15.2 Import file

`POST /programs/preview` and `POST /programs` take `scope_file` instead of
`scope_text`:

```json
{ "format": "auto | platform_csv | burp_json | generic_csv | text",
  "name": "scope.json",
  "content": "<file text>",
  "mapping": { "identifier": "Target", "type": "Kind", "in_scope": "Eligible" } }
```

| Format | Read as |
|---|---|
| `platform_csv` | the CSV export a platform offers for a program's scope (§5.2 columns) |
| `burp_json` | a Burp Suite target scope: `target.scope.include` in scope, `exclude` out of scope, disabled rules dropped; `prefix` rules are URLs; a `host` expression becomes an entry only when it names exactly one host (`^www\.example\.com$`) or every subdomain of one name (`^.*\.example\.com$`, `^(.*\.)?example\.com$`). Any other expression (`.*`, alternations, character classes, address patterns) is kept as a not-scannable item: a translation never covers more than the file says |
| `generic_csv` | any CSV with a header; `mapping` names the identifier column (required) and optionally a type and an in-scope column; a missing column is refused |
| `text` | the paste format of §5.2 |
| `auto` | `{…}` is `burp_json`, a header with `identifier`/`asset_identifier` is `platform_csv`, anything else `text` |

The bounds of a paste apply (256 KiB, 2 000 items, at least one in-scope
item); the request body allows for JSON escaping. Items then go through the
same preview, guardrails (public suffixes such as `*.com`, the deny list, the
CIDR caps refuse an entry), terms hash and attestation as a paste. The
program records `scope_source = file_import`.

### 15.3 Confidentiality

- `bounty_programs.visibility` (`private`, `public`) and `terms_text`
  (the program's own terms as pasted, at most 20 000 characters; part of the
  terms hash when set, so programs without one keep their hash).
- `bounty_program_attestations (tenant_id, program_id, user_id,
  terms_sha256, accepted_at)`: one row per person, replaced on each
  acceptance; tenant-composite key to the program, deleted with it or with
  the user. The importer's, the acceptor's of new terms and the resumer's
  acceptances are recorded by those actions; the attestation in force before
  this change is carried over by the migration.
- `POST /programs/{id}/attest {accept_terms_sha256}` (`programs:read`,
  member or owner): records the caller's acceptance of the current terms.
  It changes no authorization.
- Until the caller has accepted the current terms, `GET /programs` and
  `GET /programs/{id}` show a private program **locked**: name, platform,
  visibility, status, terms text and hash only (no scope, rules, link, sync
  or pending terms). Re-import, sync, source, pending terms and applying them
  answer `409 PROGRAM_ATTESTATION_REQUIRED`. Pause and end (narrowing) need
  membership only.
- `GET /scope/targets` and `GET /scope/targets/{id}` leave out the entries
  of private programs the caller may not see or has not accepted (404 by
  id), so a scope reader does not learn a private program's scope.
- Assets of a private program (owner decision, 2026-10-10): a
  program-only asset (§16.5) linked to private programs only, and its
  findings, are visible only to the members of one of those programs and to
  the organization's owners. Administrators and full-data roles who are not
  members get 404 by id and do not see them in lists, exports, counts,
  dashboards (also with `include_program_assets=true`), the change feed or
  the EASM overview. The rule lives in the data-scope layer: the enforcer
  gives such a caller a scope that admits every asset but the hidden ones
  (`DataScope.Unrestricted`; resolved only when something is hidden from
  them), and the one predicate (`filterspec.HiddenAssetWhere`) is added to
  every scoped read and id check; a restricted member's scope rows never
  admit a hidden asset either. An asset the organization also owns (not
  program-only) stays visible, but the program's tag and flags are left out
  of its response for non-members. Acting (scans) is not narrowed by it.
  A non-member's system tags, in responses and in the inventory's tag and
  `program_assets=only` filters, are only those derived from programs not
  hidden from them (`filterspec.ProgramHiddenSQL`), so the filter cannot
  reveal that a private program covers a shared asset. The same rule
  covers the tag suggestions (`GET /assets/tags`, data-scoped), the EASM
  overview counts and review queue (SQL, not a page filter), and the live
  notification push (a hidden asset's notice reaches only owners and the
  program's members).

| Threat | Control |
|---|---|
| Administrator browses a private program's terms | 404 unless member or owner; owner views audited |
| Member reads changed terms without re-accepting | acceptance bound to `terms_sha256`; changed terms lock the program again |
| Scope reader enumerates a private program's targets | private program entries filtered from the scope views |
| Hostile file widens scope (`.*`, `*.com`, a /8) | exact-only Burp translation; guardrails refuse public suffixes, deny list, CIDR caps; preview before commit |
| Oversized or malformed file | 256 KiB / 2 000 items, strict format errors (`PROGRAM_FILE_INVALID`) |
| Another tenant | every query tenant-scoped; attestation insert joins the program in the caller's tenant |

## 16. Public program monitor (addendum, 2026-10-10)

Public programs publish their scope. Instead of every organization pasting
it, the platform imports a signed feed of public programs, and an
organization **subscribes** to the programs it works on.

### 16.1 Feed

The collector is a separate repository, `openctemio/programfeed`, built like
the vulnerability feed of RFC-066 §5.5: a scheduled job reads public sources,
normalises each program (identity, platform, link, in-scope and out-of-scope
items, rules, terms text and their hash, `source`, `as_of`), validates and
publishes a DSSE-signed snapshot and delta with a monotonic sequence under an
offline root and an expiring key set. Installations never call the
platforms; air-gapped installations upload a bundle. The sources, their terms
and attribution are listed in the manifest (the collector's README is the
reference).

### 16.2 Importer

The platform verifies the key set against the pinned root (refusing a lower
key-set version than one accepted before), the pointer and the manifest
against the key set, refuses an unknown schema, a sequence not newer than the
applied one, a delta whose base is not the applied sequence and an expired
bundle, checks every file's size and SHA-256, re-validates every record with
the program parser (a bundle with an invalid record is refused whole) and
applies it to a platform catalog: `public_programs` (global: identity,
platform, link, items, rules, terms text and hash, source, `as_of`, removed
flag). The parser sits behind an interface so it follows the collector's
published schema. Every change to a program (items added or removed, rules
or terms changed, program closed) is recorded and fans out to the
subscriptions.

### 16.3 Subscriptions

- `POST /programs/subscriptions {public_program_id}` (`programs:write`)
  creates a program in the tenant with `scope_source = public_feed`,
  `visibility = public`, its group (the subscriber joins) and its entries
  **inactive**: status `pending_attestation`. Nothing is scanned actively.
- A member accepts the program's terms (the same attestation as an import,
  step-up): entries come into effect through `CommitEntries`
  (`program_attestation`), within the program's rules (`forbidden:
  automated_scanning` keeps them at `t0`).
- Each feed change is applied fail-safe: narrowing alone at once (the
  program stays in effect); anything that widens, or changed rules or terms,
  replaces the scope with every entry inactive (`pending_attestation`) until
  a member accepts the new terms; members are notified ("new in-scope asset in program X",
  "program X changed its terms; accept them again"). A program the feed marks
  closed is suspended.
- Program-only targets never reach platform sensors (§8, unchanged).

### 16.4 Passive by default

Before acceptance, and whenever a program forbids automated scanning, only
passive work runs on its targets: Certificate Transparency and DNS
observation by the platform, and inventory vulnerability matching
(RFC-066). The active-probe gate refuses active work because no active entry
covers the target.

### 16.5 Program assets are kept apart

- A program target becomes an asset with structural provenance:
  `asset_program_links (tenant_id, asset_id, program_id, source, attested)`
  with `source` `programfeed`, `program_manual` or `program_import`.
- System tags derived from it — `bug-bounty`, `source:<source>`,
  `platform:<platform>`, `program:<platform>:<slug>` — are written by the
  platform only: the asset update paths keep them and refuse to add or remove
  them; the web shows them in a distinct style.
- One asset per name, never a silent merge: when the organization already
  owns a name that a program also lists, the asset keeps its own provenance
  and gains the program link; it stays an organization asset. An asset is
  **program-only** while it has a program link and no other provenance; only
  program-only assets are left out of the organization's dashboards, risk
  scores, SLA and CTEM metrics by default (a toggle includes them).
- The inventory gets a "Bug bounty" filter and platform/program facets, and a
  "Program target" badge with the program and its attestation state.
- Implementation: migration `001792` (`asset_program_links`,
  `assets.system_tags`, `assets.program_only`); the program assignment pass
  keeps the links of every program (entries active or not, minus its
  exclusions; none for an ended program) and derives the tags and
  program-only in the same transaction. Program-only = linked, added after
  the earliest linked program was created, and no active own entry
  (ownership, self-attestation, letter) covers it. Dashboard queries add the
  exclusion unless the request carries `include_program_assets=true`;
  asset lists take `program_assets=only|exclude`; tag filters match system
  tags. Assets of followed public programs arrive through the collector
  ingest (§16.8).

### 16.6 Implementation notes (feed importer)

- Bundle (collector `openctemio/programfeed`, record schema
  `openctem.programfeed/v1`, its `schema/` directory is the reference):
  `keyset.dsse.json` (`application/vnd.openctem.programfeed.keyset+json`),
  `latest.dsse.json` (sequence, tag, snapshot and delta manifests, base
  sequence, expiry), `snapshot.manifest.dsse.json` with
  `snapshot-programs.jsonl.gz` and `snapshot-changes.jsonl.gz`, and
  `delta.manifest.dsse.json` with `delta-programs.jsonl.gz` and
  `delta-changes.jsonl.gz`. The record parser is an interface
  (`programfeed.RecordParser`); unknown fields are refused and every target
  is classified again by the platform's own parser.
- Verification is shared with other signed feeds (`pkg/feedsign`, the same
  DSSE, root and key-set rules as the vulnerability feed): pinned root
  (`PROGRAMFEED_ROOT_KEY_ID`, distinct from the vulnerability feed's),
  key-set version never lower, sequence newer than applied, the delta only
  when its base is the applied sequence (otherwise the snapshot), at most 7
  days valid, size and SHA-256 per file. Caps: manifest 1 MiB, file 64 MiB,
  512 MiB decompressed, 1 MiB per record, 100 000 programs.
- Apply: a snapshot replaces the catalog (programs it does not list are
  archived); a delta upserts its programs and archives the ones a
  `program_dropped` change names. A closed or paused program suspends the
  followed programs that are in effect (monitoring stops). Out of scope wins
  (the collector already resolves it; the platform's program exclusions bind
  program entries).
- A feed target is never permission to test. Entries are made only from
  targets with `confidence: published`; `inferred` targets (most records
  have `scope_published: false`) are shown as suggestions and become entries
  only when a member confirms them (`POST /programs/{id}/targets/approve`),
  which widens the program and asks for a new acceptance. The terms a person
  accepts are the hash of what they were shown (scope, rules, terms text);
  the terms text carries the terms document URL and its `terms.sha256` when
  the collector read it.
- Source: a directory (`PROGRAMFEED_DIR`, a mirror or an air-gapped upload)
  with the pinned root; both unset, nothing is imported. Controller
  `program-feed`, hourly.
- Tables: `public_programs` (global catalog with source, type, status,
  scope_published, terms URL and document hash, content hash),
  `program_feed_state` (applied sequence, highest key-set version; the apply
  locks it and refuses an older sequence), `bounty_programs.public_program_id`
  (unique per tenant), `public_synced_sha256`, `confirmed_targets`, status
  `pending_attestation`, source `public_feed` (migration `001736`).
- Fan-out is a reconcile: every tick, followed programs whose catalog
  content changed (or that are in effect while it is closed, paused or
  archived) are brought up to date, so a failed update is retried.
- Routes: `GET /programs/catalog` (`programs:read`), `POST
  /programs/subscriptions {public_program_id}` (`programs:write`, audited
  `bounty_program.subscribed`), `POST /programs/{id}/targets/approve`
  (`programs:write`, audited); acceptance is `POST /programs/{id}/reactivate`
  (step-up, terms hash), which records the person's attestation.
- Owner decision (option A, 2026-10-10): the project does not republish
  restricted platform data. Next to the signed feed, a platform operator may
  import its own **local bundle** (`programfeed build --local-only`, unsigned,
  manifest marked `collector.local_only`) from a directory the server
  configuration names (`PROGRAMFEED_LOCAL_BUNDLE_DIR`, mounted read-only;
  never set from the UI or by a tenant). It is off until a platform
  administrator enables it (`PUT /api/v1/admin/program-feed/local-bundle`,
  super_admin, a reason and a fresh console authenticator code, admin audit
  high; `GET /api/v1/admin/program-feed` shows the state and the notice that
  the records come from the hosting platforms and stay subject to their
  terms). The same strict parser, caps, sequence monotonicity (its own
  stream: `program_feed_state` row 2), delta-on-applied-base and 7-day
  validity apply; a local-only manifest is accepted only on this path and
  refused on the signed one. Local programs are marked local-only in the
  catalog (`feed_stream = local`): every in-scope target is a suggestion
  until a follower confirms it, provenance is kept per record, a signed
  record with the same id wins, and each stream archives only its own
  programs. Controller `program-feed-local`, hourly. Fetching allowlisted
  public datasets directly from the platform is a later option.

### 16.8 Program targets as collected assets (owner direction, 2026-10-10)

> Status: points 2 and 3 are built (typed scope items, port/protocol and
> path limits on entries enforced at dispatch, claim and in the signer's
> ledger, per-item qualifiers; migration `001910`). Point 1 (CTIS ingest)
> and the confidentiality of private-program assets follow. Crawlers,
> template scanners and top-ports scans run inside a limit on sensors that
> enforce it: the signed job carries the limits, the sensor's task
> forwarder refuses other ports and out-of-prefix requests, and the sensor
> reports `scope.limits@1` (docs/architecture/job-signing.md, "Scope
> limits"; sdk-go `pkg/scopelimit`).

The feed importer is an asset collector, not a second asset pipeline:

1. **Standard ingest.** Feed records are converted to the platform's CTIS
   asset ingest (the path every collector uses) with `source = programfeed`,
   `observed_at` = the record's `last_changed` (or `provenance.fetched_at`)
   and `source_run` = the feed sequence, so program targets get dedup, the
   attribute-source reconciliation (RFC-069), the change timeline, system
   tags and vulnerability matching unchanged. Program metadata (rules,
   terms, eligibility) stays in the program tables and links to the assets
   (`asset_program_links`). Re-importing the same data produces no timeline
   events.
2. **Typed scope items.** Every target type maps to an asset type and a
   scope entry: domain and wildcard to domain/subdomain; ip and cidr to
   ip_address and cidr; host:port and service targets (`api.x.com:8443/tcp`,
   `10.0.0.5:22`) to a host plus a service (open port) asset and a scope
   entry constrained to that port and protocol — scope entries gain the
   minimal port/protocol constraint, enforced at dispatch so a
   port-restricted item never authorizes a scan of other ports; a URL with a
   path to a web application/url entry with the path prefix; API endpoints
   (OpenAPI, GraphQL) to an api asset; mobile apps, source repositories,
   executables, smart contracts, AI models, hardware and other to their
   asset types where they exist, otherwise program targets without an asset
   (never scanned).
3. **Per-item qualifiers** carried through: in or out of scope (out of scope
   becomes an exclusion that wins), bounty eligibility, maximum severity,
   environment, testing instructions, required headers and test-account
   notes, and trust (published, published_by_platform, inferred).
4. **Tests**: each type maps correctly; a port-restricted item cannot start
   a scan of other ports; out of scope wins; an identical re-import makes no
   timeline events; tenant isolation.

The record parser ignores fields the collector adds within v1, so the typed
fields can ship in the collector first.

### 16.7 Plan

| PR | Content |
|---|---|
| Private programs (API) | §15: migration `001700`, file import, visibility, ACL, attestation, scope view filter |
| Private programs (web) | `/programs/new` source picker (Enter manually / Import file), visibility, locked view and acceptance |
| Feed importer | §16.2–16.3: catalog, verification, sequence and freshness, subscriptions, fan-out, notifications (fixture bundles; no network in CI) |
| Program assets | §16.5: provenance links, system tags, inventory filter, default exclusion from organization metrics |
| Local bundle source | owner option A: the operator's local-only bundle, enabled by a platform administrator (§16.6) |
| Program targets as assets | §16.8: CTIS ingest, typed scope items with port/protocol constraints, per-item qualifiers |
| Later | per-user researcher API connector (P7), passive sweep of unaccepted program targets (§16.4) |
