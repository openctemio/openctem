# Dashboard metrics: what each number counts

Every number on the dashboards is one formula over one population, and a figure
that has nothing to measure is "not measured" (null, shown as a dash), never 0
or 100. Who may see a figure, and over which assets, is in the
[authorization matrix](authorization-matrix.md#data-scope-layer-2-access-groups); this page is about
what the figures mean.

## Populations

- **Open** is the open lens of the finding status set
  (`vulnerability.OpenStatusSQL`): new, confirmed, in progress, fix applied.
  Resolved, false positive, accepted, duplicate and the pentest drafts (draft,
  in review) are not open.
- Every dashboard figure counts published findings (no pentest draft or
  in-review finding), outside branch-only findings, and follows the viewer's
  data scope and the pentest member-visibility rule.

## Finding stats (`GET /dashboard/stats`)

| Field | Formula |
|---|---|
| `findings.total` | open findings |
| `findings.by_severity` | open findings by severity (sums to `total`) |
| `findings.by_status` | published findings by status (all statuses) |
| `findings.overdue` | open findings with `sla_status` exceeded or overdue; equal to the executive summary's `sla_breached` |

## Executive summary (`GET /dashboard/executive-summary`)

| Field | Formula |
|---|---|
| `sla_compliance_pct` | `(tracked - breached) / tracked` over open findings that carry an SLA (`sla_status` set and not `not_applicable`); null when `tracked` is 0. "Open within SLA" |
| `mttr_{critical,high}_hours` | mean hours from first detection to resolution of the findings remediated in the period; null when none |
| `mttr_{critical,high}_median_hours`, `..._p90_hours`, `..._sample` | median, 90th percentile and count of the same findings; the mean of a right-skewed distribution is not the headline |
| `crown_jewels_at_risk` | crown jewels with at least one open finding (the attack-path card counts crown jewels on a reachable path; the two are labeled apart) |

`GET /dashboard/mttr-analytics` follows the same rule: `overall_hours`,
`overall_median_hours` and `overall_p90_hours` are null when nothing was
remediated, and a severity or priority bucket with no remediated finding is
left out.

## Velocity (`GET /dashboard/velocity`)

New findings per week by `created_at` and remediated findings per week by
`resolved_at`, from two range scans over the window bucketed by week and joined
to the week series (an equality test pins the result to the previous per-week
join).

## Threat intelligence (`GET /threat-intel/stats`)

`kev.tenant_open_count` is the tenant's open findings that reference a KEV
CVE; `kev.past_due_count` is the subset past its KEV due date. `kev.total_entries`
is the size of the global catalog and is context, not exposure.
