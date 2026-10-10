# Bug-bounty programs

Design: [RFC-065](../rfcs/RFC-065-bug-bounty-programs.md). Scope model:
[RFC-054](../rfcs/RFC-054-scope-model.md), [active-probe-gate.md](active-probe-gate.md).

A **program** is a bug-bounty or disclosure program a person in the
organization tests under its published rules. It owns scope entries
(`authorization_source = program`), exclusions for the items it lists as out
of scope, its rules and a group whose members work on it.

## Where a program target is decided

```
paste / CSV ──► bountyprogram.ParseScope ──► items (in / out / not scannable)
                                   │
                    RFC-054 guardrails (PSL, deny list, CIDR caps)
                                   │
       preview ──► terms_sha256 ◄── import / re-import / reactivate (step-up + attestation)
                                   │
          scope_targets (program)  +  bounty_program_exclusions  +  bounty_programs
                                   │
   scan trigger ──► one authority check (scopeauth, unchanged) ──► platform sensors?
                                                                   └─ never for program-only targets
                                   │
              scan_run_scope_snapshots ──► scope_snapshots (sha256, body)
```

## Rules of the model

- **The authority check does not change.** A program entry is an ordinary
  entry: it covers a target while it is active. Suspend and end deactivate the
  program's entries; re-import deletes the entries of items no longer listed.
- **No second approver for program entries.** The importer's attestation of
  the program's terms (program URL, rules, in and out of scope, hashed)
  replaces it. A changed paste or changed rules need a new attestation; the
  server refuses a hash that does not match what it computes.
- **Ownership scope is untouched by programs.** The program routes create
  only program entries; the general scope routes refuse to create one and
  refuse widening one.
- **Own sensors only.** The trigger never routes a target that only program
  entries cover to platform sensors, in any `SCOPE_ACTIVE_PROOF` mode.
- **Tier.** Program entries allow at most T1, T0 when the program forbids
  automated scanning.
- **Program exclusions bind program entries only.** An out-of-scope item (and
  the unlisted apex of a program wildcard) is a program exclusion: no
  `program` entry of the organization covers that name, for any program or
  researcher. The organization's own entries (ownership, self-attestation,
  letters) and the RFC-054 exclusions are untouched; the program detail shows
  where a program exclusion overlaps the organization's own scope.

## Researcher role and data scope

- Permissions `attack_surface:programs:read|write`; the built-in Researcher
  role (`…0005`) holds them with scans, findings and read-only assets and
  sensors. Owners and administrators hold every program permission.
- Every program has a group (type `project`). The program assignment pass
  keeps `asset_owners` rows with `assignment_source = 'program'` for the
  assets the program's active entries cover; the `asset_owners` trigger keeps
  `user_accessible_assets` current. A member of the group sees those assets
  and their findings and nothing else of the organization (Layer 2, RFC-050).
- Program lists and details show a restricted caller only their programs; a
  program they may not see answers 404.
- Act scope: a restricted member may scan a typed target an active entry of
  one of their programs covers.

## Rules at delivery

A program's rules travel with every job a sensor gets (RFC-065 §12). Command
delivery (`command.Service` Poll, claim-N, claim by id) asks
`bountyprogram.Service.JobRules` for the programs whose in-effect entries
cover the job's targets (program exclusions applied, the command's own
tenant only):

- outside a covering program's testing windows the job stays pending;
- two programs with different values for one header, or two User-Agents:
  the job fails with `PROGRAM_RULES_CONFLICT`;
- otherwise the delivered copy carries the headers and User-Agent in
  `http_policy` and a `rate_limit` capped at the smallest program rate; the
  stored command is unchanged;
- headers or a User-Agent go only to a sensor whose SDK is v0.19.0 or later
  (older sensors would ignore them); a failed lookup withholds the job.

The trigger refuses the same cases up front (`PROGRAM_OUTSIDE_WINDOW`,
`PROGRAM_RULES_CONFLICT`). Programs cannot require credential or connection
headers.

## Letters of authorization

A signed letter (`/api/v1/scope/letters`, RFC-065 §13) is stored as an
attachment with its SHA-256 and a validity of at most two years. It
authorizes nothing by itself: a scope entry with authorization source
`authorization_letter` names it, goes through the approval policy, and is in
effect only while the letter is valid (the in-effect read joins the letter).
Revoking a letter (scope approvers) or its expiry stops every entry naming it
at once. A letter's attachment cannot be deleted while the letter exists.
The job signer's scope ledger follows (RFC-040 §11.5): a revocation removes
the letter's entries, and a letter entry's ledger expiry is never later than
the letter's end.

## Scope sync

A program's scope can come from the researcher API of the platform that runs
it (`program_api`: handle, username and an API token stored encrypted and
never returned) or from a scope file the program publishes on its own
registrable domain (`program_file`), read with the SSRF-safe HTTP client
(RFC-065 §14). A sync, on demand or by the controller, applies narrowing at
once (removed entries, new program exclusions; a closed program is suspended)
and keeps widening as pending terms: nothing new authorizes until a member
accepts the pending terms hash (`/pending/apply`, step-up, audited). Every
sync write goes through the job signer's ledger hook (`CommitEntries`).

## Private programs

A program is `private` (default for new programs) or `public` (RFC-065 §15).
`/programs/new` starts from a source: entered by hand or imported from a file
(the platform's CSV export, a Burp Suite target scope, any CSV with a column
mapping); no link or credential is needed. A Burp host expression becomes an
entry only when it names exactly one host or one name's subdomains.

```
caller ──► canSee (access.go)
             public : full-data caller or program member
             private: owner or program member          (else 404, like another tenant)
        ──► attested? (bounty_program_attestations.terms_sha256 == program.terms_sha256)
             no : locked view (name, platform, terms text) ; details 409 PROGRAM_ATTESTATION_REQUIRED
             yes: details ; every view of a private program audited (bounty_program.viewed)
scope views (GET /scope/targets[/{id}]) leave out private program entries the caller may not see
```

A change of terms locks the program again for everyone until they accept the
new hash (`POST /programs/{id}/attest`).

## Public program monitor

Public programs come from a signed feed (`openctemio/programfeed`, built like
the vulnerability feed of RFC-066 §5.5). The platform never calls the
bug-bounty platforms.

```
PROGRAMFEED_DIR ──► programfeed.VerifyDir (pinned root, key-set version ≥ last,
                     sequence > applied, not expired, size + SHA-256 per file)
                 ──► ReadPrograms (RecordParser v1, every record validated)
                 ──► public_programs + program_feed_state (one transaction)
                 ──► reconcile: subscribed programs whose terms differ
                        narrowing only  → applied at once, still in effect
                        widening / rules / terms / pending → entries inactive,
                                          pending_attestation, admins notified
                        closed / removed → suspended
POST /programs/subscriptions ──► tenant program (public_feed), entries inactive
POST /programs/{id}/reactivate (step-up, terms hash) ──► entries in effect (CommitEntries)
```

Before acceptance only passive work runs: the active-probe gate finds no
active entry. Program assets will carry provenance and system tags and be
left out of the organization's own metrics by default (RFC-065 §16.5).

## Evidence

Every scan run links to a scope snapshot: the entry that covered each of its
targets (with source, program and tier), those programs with their
attestation and program exclusions, and the count of uncovered targets.
Identical authority gives the same hash and one stored body.
`GET /api/v1/scan-runs/{id}/scope-snapshot` returns it to callers who may see
the run and hold `scope:read` or `programs:read`.

## Files

| Path | What |
|---|---|
| `pkg/domain/bountyprogram/` | program entity, rules, scope parser, terms hash |
| `internal/app/bountyprogram/` | import, re-import, lifecycle, attestation, assignment pass |
| `internal/app/scopeauth/` | program exclusions bind program entries; `ProgramOnly`, `CoveredByPrograms` |
| `internal/app/scan/active_proof.go` | platform-sensor refusal for program-only targets |
| `internal/app/scan/scope_snapshot.go`, `internal/app/scope/snapshot.go` | snapshot per run |
| `internal/infra/postgres/bounty_program_assign.go` | program assignment pass (data scope) |
| `migrations/001495_bounty_programs.*` | tables, columns, permissions, Researcher role |
| `pkg/domain/bountyprogram/windows.go`, `internal/app/bountyprogram/rules.go` | testing windows, the rules a job carries |
| `internal/app/command/program_rules.go`, `internal/app/scan/program_rules.go` | rules at delivery and at trigger |
| `pkg/domain/scope/letter.go`, `internal/app/scope/letters.go` | letters of authorization |
| `pkg/domain/bountyprogram/sync.go`, `internal/app/bountyprogram/sync.go`, `internal/infra/bountysource/` | scope sync |
| `migrations/001549_authorization_letters.*`, `migrations/001610_bounty_program_sync.*` | letters, sync state |
| `pkg/domain/bountyprogram/scope_file.go` | scope files: platform CSV, Burp scope JSON, CSV with a column mapping |
| `internal/app/bountyprogram/access.go` | visibility, per-person attestation, hidden program entries |
| `migrations/001700_private_programs.*` | visibility, terms text, optional link, attestations |
| `pkg/feedsign/` | shared verification of signed feed bundles (DSSE, root, key set) |
| `pkg/programfeed/` | program feed bundle: verify, read records (`V1` parser) |
| `internal/app/programfeed/`, `internal/infra/controller/program_feed.go` | importer and reconcile |
| `internal/app/bountyprogram/subscription.go`, `internal/infra/postgres/public_program_repository.go` | subscriptions, catalog |
| `migrations/001710_public_program_feed.*` | catalog, feed state, subscriptions |
