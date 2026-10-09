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
       preview ──► terms_sha256 ◄── import / re-import / resume (step-up + attestation)
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
  entry: it covers a target while it is active. Pause and end deactivate the
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

## Evidence

Every scan run links to a scope snapshot: the in-effect entries (with source,
program and tier), in-effect exclusions and active programs with their
attestation. Identical scope gives the same hash and one stored body.
`GET /api/v1/scans/runs/{id}/scope-snapshot` returns it.

## Files

| Path | What |
|---|---|
| `pkg/domain/bountyprogram/` | program entity, rules, scope parser, terms hash |
| `internal/app/bountyprogram/` | import, re-import, lifecycle, attestation, assignment pass |
| `internal/app/scopeauth/` | `OwnedCover`: whether a non-program entry covers a target |
| `internal/app/scan/active_proof.go` | platform-sensor refusal for program-only targets |
| `internal/app/scan/scope_snapshot.go` | snapshot per run |
| `migrations/001454_bounty_programs.*` | tables, columns, permissions, Researcher role |
