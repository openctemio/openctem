# RFC-144: Application security posture: branches, CI closure, code-to-runtime context

| | |
|---|---|
| Status | Draft (2026-11-02). Implemented: none yet. Designed: the reference model (§3), counting rules (§4), CI default-branch closure (§5), reference lifecycle (§6), application context (§7) |
| Scope | api (ingest, cirun, scmapp, findings, branches, ticketing), web (repository workspace, finding detail, CI setup), ci (CLI and templates), ctis (report metadata) |
| Related | RFC-008 (shift-left CI scanning), RFC-015 (remediation groups), RFC-043 (deduplication and identity), RFC-051 (CI runner identity and gate), `docs/architecture/branch-only-findings.md`, `docs/architecture/finding-closure.md`, `docs/architecture/shift-left-ci-scanning.md` |

## 1. Summary

OpenCTEM collects code findings (SAST, SCA, secrets, IaC, container) from CI and sensors, runtime
findings (DAST, network) from sensors, and human findings (pentest, bug bounty). This RFC makes the
application view answer three questions precisely:

1. **Where is a vulnerability?** On which branches, pull requests and release tags of a repository it
   is present, since which commit, and in which commit it was fixed.
2. **What counts?** Which findings make up a repository's (or an application's) posture, counted once.
3. **When does it close?** A fix merged to a counting branch, proven by a qualified CI run, closes the
   finding and moves its ticket; nothing weaker does.

It keeps the existing core: one finding per (tenant, asset, identity key), per-branch occurrences,
branch-only findings, the verified base reference of a pull request, the fail-closed gate.

## 2. Problems (verified on develop, 2026-11-02)

| # | Problem | Where |
|---|---|---|
| P1 | Branch counters and branch compare read `findings.branch_id` (one headline branch per finding) while the findings list reads occurrences. A finding present on `main` and `feature/x` counts only on `main`; comparing `main` with `feature/x` reports it fixed on the feature branch. | `migrations/003345_branch_finding_counts_per_statement.up.sql`, `internal/infra/postgres/branch_repository.go` `CompareBranches` |
| P2 | A CI run never changes a finding's status (decision O11). A fix merged to the default branch leaves the finding open for ever; only its occurrence becomes `auto_fixed`. | `internal/app/ingest/service.go` step 3, `docs/architecture/shift-left-ci-scanning.md` |
| P3 | In a repository with no known default branch every reference counts, pull request references included. | `branch_counts_as_exposure` (migration 002147) |
| P4 | Pull request close or merge, branch deletion and branch rename are not received. Pull request findings linger until expiry; a manually deleted branch cascades its occurrences away. | `internal/app/scmapp/service.go`, `internal/app/asset/branch.go` |
| P5 | A tag pipeline records no reference, so its findings count as exposure. | `pkg/domain/cirun/claims.go` `ReportBranchName` |
| P6 | No path scope inside a repository (monorepos), no ownership from the code host, no link from a repository to the image and service it ships to. | — |
| P7 | A scan-driven resolve or reopen does not transition the linked ticket (comment only). | `internal/app/retest/announce.go` |

## 3. Reference model

```
repository
 ├─ reference: branch | pull request | tag
 │    counts   = default or protected (code host or administrator); pull request and tag never count
 │    state    = active | merged | deleted
 │    └─ occurrence(finding, reference): open | fixed | gone
 │         first commit (introduced here), fixed commit, first/last seen
 ├─ project: path glob → owner, business service              (monorepo)
 └─ built image (digest, revision) → workload / service        (code to runtime)

finding (asset, identity key): one status, one triage, one ticket, one SLA, one remediation task
```

- **One finding, many occurrences.** The identity key has no branch input. A false positive, an
  accepted risk, a ticket or a remediation task holds on every reference.
- **Occurrence states.** `open` (seen by the latest qualified run of that reference), `fixed` (a
  qualified run of that reference no longer saw it; records the run's commit), `gone` (the reference
  was merged, closed or deleted). `gone` replaces the cascade delete, so history survives.
- **Introduced in / fixed in.** The occurrence's first commit is where the finding was first seen on
  that reference; the fixed commit is the commit of the run that no longer saw it.

## 4. Counting rules

| View | Population |
|---|---|
| Organization, dashboards, SLA, notifications, ticket rules | Open findings that are not branch-only, counted once (unchanged). |
| Repository or project posture | The same population restricted to the repository or project. |
| Branch page and branch counters | Findings with an `open` occurrence on that reference whose status is open. |
| Branch compare A → B | By occurrence state: new on B, fixed on B, still open on both. |
| Pull request | The run's identity keys against the `open` occurrences of the verified base reference (unchanged). |
| Release tag | The occurrences of the tag reference. |

A reference counts as exposure when it is the default or a protected branch. Pull request, fork and
tag references never count, also in a repository with no known default branch; a CI run records the
default branch from its verified token before its findings are written.

## 5. CI default-branch closure

A finding closes automatically when **every counting reference** that held it has a `fixed`
occurrence written by a **qualified run**:

- the run is bound to an OIDC-verified CI run of that reference (or a command-bound sensor scan);
- the job completed successfully and reported `coverage_type = full`;
- same scan key (pipeline, job, tool, SARIF category) as the occurrence's last sighting;
- same ruleset digest (the CLI sends a digest of the rule set and tool version) and a path scope that
  covers the finding's file.

The close goes through the tenant's closure mode (`auto`, `review`, `off`) and stores the closure
evidence (run, commit, tool, ruleset digest). A changed ruleset, a removed tool, an excluded path or a
failed, cancelled or partial job never closes: the finding is marked *no longer scanned*. Secrets
never close by absence. A finding fixed on the default branch but open on a protected release
branch stays open and shows both lines.

A later qualified run of a counting reference that sees the finding again reopens it (regression
rules of `finding-closure.md`); a pull request or feature run never reopens it.

## 6. Reference lifecycle

| Event (code host webhook, signature verified) | Effect |
|---|---|
| Pull request closed or merged | Its reference becomes `merged`/`deleted`; its occurrences become `gone`. A finding whose only occurrences are `gone` closes as `obsolete_source` (not counted as remediated). The target branch's next run decides the rest. |
| Branch deleted | Same as above for the branch. |
| Branch created with the head of a branch deleted in the same push | Rename: occurrences move to the new reference. |
| Protection added or removed | Counting changes; branch-only findings are promoted on add (exists). A finding that already counts is never hidden. |

GitLab gets an inbound webhook with a per-connection secret compared in constant time.

## 7. Application context

- **Projects.** `repository_projects(repository, name, path globs, owner, business service)`. A
  finding with a file path belongs to the longest matching project; counts, owners and gate policy can
  be set per project. Vendored and generated paths are projects of their own kind and carry a default
  suppression rule for SAST (opt-in).
- **Ownership.** The default branch's `CODEOWNERS` file is read through the code host connection and
  turned into computed owners by path; assignment uses them unless a person assigned the finding.
- **Code to runtime.** A CI run that builds an image reports its digest and revision; the repository is
  linked to the image (`built_from`) and, through the existing digest links, to the workload and
  service. The exposure of that service (internet facing, crown jewel) flows into the priority of the
  repository's open findings for the deployed revision.
- **Runtime evidence.** IAST and RASP reports enter as their own source, keyed on the service like
  DAST, with an optional code location that links them to the matching code finding (a same-issue
  link, never a merge).

## 8. Remediation loop

- A scan-driven resolve or reopen transitions the linked ticket (opt-in push, echo guard, fallback to a
  comment when the workflow has no matching transition).
- The pull request comment lists new, fixed in this pull request, reintroduced and pre-existing
  findings; stored fix code is offered as a suggestion, never committed.

## 9. Security

- Every query and trigger is tenant-scoped; occurrence counts are taken per branch within the
  branch's repository tenant.
- The reference and its default flag come from the verified CI token or the code host, never from the
  report. Pull request references never count, so a pull request cannot shape a baseline.
- Closure needs proof of origin (the CI run binding) and proof of coverage (ruleset digest, path
  scope, job status); anything missing fails closed.
- Webhooks are signature-verified with replay protection; installation tokens stay scoped to one
  repository; ticketing credentials stay encrypted and are never written in plaintext.
- Secret values are never copied into tickets, pull request comments or exports.

## 10. Plan

| Order | Change |
|---|---|
| 1 | Branch counters and compare from occurrences (P1). |
| 2 | CI default-branch closure with ruleset digest and path scope (P2; api, ci, ctis). |
| 3 | Pull request and tag references never count; default branch recorded first (P3, P5). |
| 4 | Occurrence sweep honours run-level failures. |
| 5 | Repository workspace text through i18n; counting labels. |
| 6 | Reference lifecycle from webhooks; `gone` state; GitLab webhook (P4). |
| 7 | Fixed commit per occurrence; "where it is" in the finding detail. |
| 8 | Ticket transitions on scan-driven resolve and reopen (P7). |
| 9 | `CODEOWNERS` ownership; projects; code-to-runtime link; runtime evidence source (P6). |
