# RFC-152: Finding practices

| | |
|---|---|
| Status | Partly implemented (2026-11-07): practice column, derivation, filters; switch, compliance policy and backfill in progress |
| Scope | api (findings column, derivation, filters, query language, MCP, SLA policy, dashboards, backfill command), web (findings practice switch, SLA policy form) |
| Architecture | [finding-practices.md](../architecture/finding-practices.md) |
| Related | RFC-048 (list query contract), RFC-115 (query language), RFC-017 (CTEM priority) |

## 1. Problem

A finding has a kind (`finding_type`) and a detection technique (`source`),
but nothing says which program triages it. Benchmark check results from a
host scan (a CIS check that FAILED) get the scanner's severity, then a
priority class and a vulnerability SLA window, and sit in the same lists and
SLA figures as exploitable vulnerabilities. Application security, network
vulnerability assessment, attack surface, cloud posture and offensive testing
each need their own slice of the findings, with their own policy, through
simple views and the existing filters and query language.

## 2. Decisions

1. **One derived dimension, `practice`**, stored on the finding, indexed,
   with nine fixed values: `aspm`, `infra`, `external`, `cloud`,
   `compliance`, `offensive`, `identity`, `runtime`, `other`. It names the
   program that owns the triage, not where the asset sits (exposure stays a
   filter) and not the kind of weakness (`finding_type` stays). Tenants do not
   add practices: a custom slice is a saved view.
2. **One Go function derives it** (`vulnerability.DerivePractice`, first
   matching rule wins) at write time, from the finding (type, source, tool,
   pentest campaign) and its asset (type, internet-facing). It is stored, not
   computed at read, so the list filter uses an index and policy can be chosen
   when a finding is written. There is no SQL copy of the rules: the backfill
   command calls the same function.
3. **Compliance means a benchmark check result** (`finding_type =
   compliance`), whatever detected it, and nothing else. Misconfigurations
   from infrastructure-as-code or cloud posture keep vulnerability policy
   (`aspm`, `cloud`): a public storage bucket is a real exposure. No rule can
   move a finding into or out of compliance, so the longer compliance policy
   cannot park a vulnerability.
4. **Forward only.** Closed findings keep their practice; a re-sighting
   re-derives only a finding never derived or one whose type changed.
5. **Filters, not a new engine.** `practice` and `compliance_result` are
   fields of the findings registry, so the list, stats, groups, export, saved
   views, the query language and the MCP `list_findings` tool accept them
   with the data scope applied per caller.
6. **The findings list opens on "Vulnerabilities"** (every practice except
   compliance, `practice_not=compliance`), with one switch to Compliance, to
   each practice and to everything; the choice is part of the URL and of
   saved views.
7. **Compliance has its own SLA policy.** SLA policies carry an optional
   practice. A compliance finding is governed only by compliance policies
   (asset, then tenant, then the platform's compliance defaults: P1 30, P2 90,
   P3 180 days); a policy without a practice never governs it. Compliance
   findings are left out of vulnerability SLA figures and dashboard facts.
8. **Data changes are explicit.** Existing rows read as `other` until an
   operator runs the `finding-practice` command, a dry run by default that
   reports aggregates per tenant (practice counts, moves, SLA deadlines that
   would change). Apply needs `-apply`.

## 3. Derivation rules

| # | Condition | Practice |
|---|---|---|
| 1 | finding type compliance | compliance |
| 2 | source pentest, red team or bug bounty, or a pentest campaign | offensive |
| 3 | source rasp, waf, siem, threat intel | runtime |
| 4 | source sast, sca, iac; a secret on a repository; licence or web3 type | aspm |
| 5 | source container: on a host or cluster infra, otherwise aspm | aspm / infra |
| 6 | source cspm | cloud |
| 7 | asset type identity | identity |
| 8 | source easm | external |
| 9 | source va | infra |
| 10 | source dast: an application testing tool aspm; an internet-facing asset external; otherwise infra | aspm / external / infra |
| 11 | otherwise by asset type (repository aspm; host, address, service, database, network, cluster infra; cloud account, storage cloud; domain, certificate, application external) | per type |
| 12 | otherwise | other |

## 4. Planned

- Practice of a scan definition (who ran it settles template checks), tenant
  practice rules between non-compliance practices, a person's override.
- Compliance priority from benchmark level, asset criticality and
  environment (never P0/P1 automatically), the benchmark level column.
- Check state per asset and control (passes stop being open findings), a pass
  rate per benchmark and framework, a remediation key per control.
- Practice in the dashboard fact keys, starter views, default views per user,
  team, role and tenant, team pins, view subscriptions.
- A short search-bar form of the query language.

## 5. Security

- The filters are registry fields: the tenant, data scope, pentest campaign
  membership and mandatory filters are applied per caller on every read, so a
  shared view or a practice count never reaches rows outside the caller's
  scope. Tests: a scoped member filtering on compliance sees only in-scope
  rows; another tenant's rows never appear.
- The asset facts the derivation reads are pinned to the finding's tenant:
  the repository reads them by tenant, and ingest attaches only the facts of
  the batch tenant's own stored assets to the batch tenant's findings.
- Compliance is fixed to the finding type (decision 3).
- The backfill command changes nothing without `-apply`, reads only
  aggregates in its report, and opens its connection read-only for a dry run.
